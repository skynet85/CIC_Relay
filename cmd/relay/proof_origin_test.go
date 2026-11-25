package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"centralrelay/core/cabinet"
	"centralrelay/pkg/obs"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fakeVerifier is a cabinet.TraceVerifier with a fixed answer; it keeps what it was asked.
type fakeVerifier struct {
	ok      bool
	err     error
	gotData []byte
	gotSig  string
}

func (f *fakeVerifier) Verify(_ context.Context, data []byte, sig string) (bool, error) {
	f.gotData, f.gotSig = data, sig
	return f.ok, f.err
}

// v2Artifact returns a well-formed, signed v2 ProofArtifact.
func v2Artifact() *ProofArtifact {
	tr := &cabinet.ProofTrace{
		WorkflowID:   "wf@1.0",
		SourceDigest: "src123",
		ChainVersion: cabinet.ChainVersionV2,
		Status:       cabinet.TraceStatusCompleted,
		Timestamp:    "2026-01-01T00:00:00Z",
		Steps: []cabinet.ProofTraceStep{
			{Name: "step1", Module: "mod@1.0", ModuleChecksum: "sum", InputHash: "aaa", OutputHash: "bbb"},
		},
		Signature: "vault:v1:sig",
	}
	tr.ChainHash = cabinet.ComputeChainHashV2(tr)
	return ProofArtifactFromTrace(tr)
}

func TestVerifyProofArtifact_V2_IsValidWithoutTheV1Warning(t *testing.T) {
	r := VerifyProofArtifact(v2Artifact())
	assert.True(t, r.Valid, "%+v", r)
	assert.Empty(t, r.Errors)
	assert.Empty(t, r.Warnings)
	assert.False(t, r.Authentic, "integrity alone never claims authenticity")
}

func TestVerifyProofArtifact_V2_BindsTimestampAndModuleChecksum(t *testing.T) {
	a := v2Artifact()
	a.Timestamp = "2030-01-01T00:00:00Z"
	assert.False(t, VerifyProofArtifact(a).Valid, "a changed timestamp breaks a v2 chain")

	a = v2Artifact()
	a.Steps[0].ModuleChecksum = "other-binary"
	assert.False(t, VerifyProofArtifact(a).Valid, "a different module binary breaks a v2 chain")
}

func TestVerifyProofArtifact_V1_WarnsWhatItDoesNotBind(t *testing.T) {
	a := validProofArtifact()
	r := VerifyProofArtifact(a)
	assert.True(t, r.Valid)
	assert.True(t, warningContains(r.Warnings, "chain_version v1"), "warnings: %v", r.Warnings)

	a.ChainVersion = cabinet.ChainVersionV1
	r = VerifyProofArtifact(a)
	assert.True(t, r.Valid, "an explicit v1 verifies like an implicit one")
	assert.True(t, warningContains(r.Warnings, "chain_version v1"))
}

func TestVerifyProofArtifact_UnsupportedVersion(t *testing.T) {
	a := v2Artifact()
	a.ChainVersion = "v9"
	r := VerifyProofArtifact(a)
	assert.False(t, r.Valid)
	assert.True(t, warningContains(r.Errors, "not supported"), "errors: %v", r.Errors)
}

func TestVerifyProofArtifact_Outcome(t *testing.T) {
	t.Run("failed run with its failed step is valid and says so", func(t *testing.T) {
		tr := v2Artifact().toTrace()
		tr.Status, tr.FailedStep = cabinet.TraceStatusFailed, "step2"
		tr.ChainHash = cabinet.ComputeChainHashV2(tr)
		r := VerifyProofArtifact(ProofArtifactFromTrace(tr))
		assert.True(t, r.Valid, "%+v", r)
		assert.True(t, warningContains(r.Warnings, "did not complete"))
	})
	t.Run("failed without failed_step", func(t *testing.T) {
		a := v2Artifact()
		a.Status = cabinet.TraceStatusFailed
		r := VerifyProofArtifact(a)
		assert.False(t, r.Valid)
		assert.True(t, warningContains(r.Errors, "requires failed_step"))
	})
	t.Run("failed_step on a completed run", func(t *testing.T) {
		a := v2Artifact()
		a.FailedStep = "step2"
		r := VerifyProofArtifact(a)
		assert.False(t, r.Valid)
		assert.True(t, warningContains(r.Errors, "failed_step is set"))
	})
	t.Run("unknown status", func(t *testing.T) {
		a := v2Artifact()
		a.Status = "partial"
		r := VerifyProofArtifact(a)
		assert.False(t, r.Valid)
		assert.True(t, warningContains(r.Errors, "status must be"))
	})
}

func TestVerifyProofAuthenticity(t *testing.T) {
	ctx := context.Background()
	valid := func(a *ProofArtifact) VerifyResult { return VerifyProofArtifact(a) }

	t.Run("good signature is authentic", func(t *testing.T) {
		a := v2Artifact()
		v := &fakeVerifier{ok: true}
		r := VerifyProofAuthenticity(ctx, v, a, valid(a))
		assert.True(t, r.Valid)
		assert.True(t, r.Authentic)
		assert.Equal(t, a.ChainHash, string(v.gotData), "the signature is checked over the chain hash")
		assert.Equal(t, a.Signature, v.gotSig)
	})
	t.Run("bad signature invalidates", func(t *testing.T) {
		a := v2Artifact()
		r := VerifyProofAuthenticity(ctx, &fakeVerifier{ok: false}, a, valid(a))
		assert.False(t, r.Valid)
		assert.False(t, r.Authentic)
		assert.True(t, warningContains(r.Errors, "does not verify"))
	})
	t.Run("backend error is a warning, not authentic", func(t *testing.T) {
		a := v2Artifact()
		r := VerifyProofAuthenticity(ctx, &fakeVerifier{err: errors.New("vault down")}, a, valid(a))
		assert.True(t, r.Valid)
		assert.False(t, r.Authentic)
		assert.True(t, warningContains(r.Warnings, "backend error"))
	})
	t.Run("no verifier configured", func(t *testing.T) {
		a := v2Artifact()
		r := VerifyProofAuthenticity(ctx, nil, a, valid(a))
		assert.True(t, r.Valid)
		assert.False(t, r.Authentic)
		assert.True(t, warningContains(r.Warnings, "no verification key"))
	})
	t.Run("unsigned artifact", func(t *testing.T) {
		a := v2Artifact()
		a.Signature = ""
		v := &fakeVerifier{ok: true}
		r := VerifyProofAuthenticity(ctx, v, a, valid(a))
		assert.True(t, r.Valid)
		assert.False(t, r.Authentic)
		assert.True(t, warningContains(r.Warnings, "unsigned"))
		assert.Nil(t, v.gotData, "nothing to check")
	})
	t.Run("an invalid chain is never checked for a signature", func(t *testing.T) {
		a := v2Artifact()
		a.ChainHash = "forged"
		v := &fakeVerifier{ok: true}
		r := VerifyProofAuthenticity(ctx, v, a, valid(a))
		assert.False(t, r.Valid)
		assert.False(t, r.Authentic)
		assert.Nil(t, v.gotData)
	})
	t.Run("an incoming Authentic flag is not trusted", func(t *testing.T) {
		a := v2Artifact()
		a.Signature = ""
		in := valid(a)
		in.Authentic = true
		assert.False(t, VerifyProofAuthenticity(ctx, nil, a, in).Authentic)
	})
}

func TestProofArtifact_RoundTripsThroughTrace(t *testing.T) {
	a := v2Artifact()
	b := ProofArtifactFromTrace(a.toTrace())
	assert.Equal(t, a, b)
}

func TestProofVerifyHandler_ReportsAuthenticity(t *testing.T) {
	body, err := json.Marshal(ProofVerifyRequest{ProofArtifact: v2Artifact()})
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		verifier  cabinet.TraceVerifier
		authentic bool
	}{
		{"with the relay key", &fakeVerifier{ok: true}, true},
		{"without a key", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestProofVerifyServer(t)
			s.traceVerifier = tc.verifier
			w := httptest.NewRecorder()
			s.proofVerifyHandler(w, httptest.NewRequest(http.MethodPost, "/v1/proof/verify", bytes.NewReader(body)))
			require.Equal(t, http.StatusOK, w.Code)
			var resp ProofVerifyResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.True(t, resp.Valid)
			assert.Equal(t, tc.authentic, resp.Authentic)
		})
	}
}

func TestEvidenceRequiredFromEnv_Prod(t *testing.T) {
	t.Setenv("CIC_TRUST_MODE", TrustModeProd)

	t.Setenv("CIC_EVIDENCE_REQUIRED", "")
	got, err := evidenceRequiredFromEnv()
	require.NoError(t, err)
	assert.True(t, got, "prod requires evidence unless told otherwise")

	t.Setenv("CIC_EVIDENCE_REQUIRED", "true")
	got, err = evidenceRequiredFromEnv()
	require.NoError(t, err)
	assert.True(t, got)

	t.Setenv("CIC_EVIDENCE_REQUIRED", "false")
	_, err = evidenceRequiredFromEnv()
	assert.Error(t, err, "prod cannot switch evidence off")

	t.Setenv("CIC_TRUST_MODE", "dev")
	t.Setenv("CIC_EVIDENCE_REQUIRED", "")
	got, err = evidenceRequiredFromEnv()
	require.NoError(t, err)
	assert.False(t, got, "dev keeps the old default")
}

func TestSetHandler_FailedRun_AnchorsTheTraceToItsChain(t *testing.T) {
	failed := &cabinet.ExecutionFailedError{
		Err:   errors.New("make test exit 2"),
		Trace: &cabinet.ProofTrace{ChainHash: "abc123", FailedStep: "boom@1.0.fail(a) -> b"},
		Proof: &cabinet.ProofStatus{Persisted: true},
	}
	mockAPI := new(mockCabinetService)
	mockAPI.On("GetWorkflow", mock.Anything).Return(&cabinet.Workflow{}, nil)
	mockAPI.On("Setx", mock.Anything, mock.Anything).Return(nil, failed)

	logger := logrus.New()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	sink := &obs.CaptureSink{}
	server := &relayServer{api: mockAPI, config: &config{MaxJSONInputSize: 1024}, logger: logger, traceSink: sink, logSink: sink, metricSink: sink}

	w := httptest.NewRecorder()
	server.setHandler(w, httptest.NewRequest(http.MethodPost, "/set", bytes.NewReader([]byte(`{"workflow_id":"any"}`))))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	require.Len(t, sink.Traces, 1)
	assert.Equal(t, "abc123", sink.Traces[0].Attrs["chain_anchor"], "the failed run's trace is linked to its recorded chain")
	assert.Contains(t, logs.String(), "abc123")
	assert.Contains(t, logs.String(), "proof_persisted")
}
