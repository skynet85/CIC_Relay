package cabinet

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureRecorder is an ExecutionRecorder that keeps every trace it is handed.
type captureRecorder struct {
	traces []*ProofTrace
	err    error
}

func (c *captureRecorder) Record(_ context.Context, _ string, tr interface{}) error {
	if t, ok := tr.(*ProofTrace); ok {
		c.traces = append(c.traces, t)
	}
	return c.err
}

// fakeSigner is a TraceSigner that returns a fixed signature (or error) and keeps what it signed.
type fakeSigner struct {
	sig    string
	err    error
	signed [][]byte
}

func (f *fakeSigner) Sign(_ context.Context, data []byte) (string, error) {
	f.signed = append(f.signed, append([]byte(nil), data...))
	return f.sig, f.err
}

func v2Trace() *ProofTrace {
	return &ProofTrace{
		WorkflowID:   "wf@1.0",
		SourceDigest: "src",
		ChainVersion: ChainVersionV2,
		Status:       TraceStatusCompleted,
		Timestamp:    "2026-01-01T00:00:00Z",
		Steps: []ProofTraceStep{
			{Name: "s1", Module: "m@1.0", ModuleChecksum: "sum-a", InputHash: "in", OutputHash: "out"},
		},
	}
}

func TestComputeChainHashV2_BindsEveryField(t *testing.T) {
	base := ComputeChainHashV2(v2Trace())
	require.Len(t, base, 64)
	assert.Equal(t, base, ComputeChainHashV2(v2Trace()), "deterministic")

	mutations := map[string]func(*ProofTrace){
		"source_digest":   func(p *ProofTrace) { p.SourceDigest = "src2" },
		"workflow_id":     func(p *ProofTrace) { p.WorkflowID = "wf@2.0" },
		"status":          func(p *ProofTrace) { p.Status = TraceStatusFailed },
		"failed_step":     func(p *ProofTrace) { p.FailedStep = "s2" },
		"timestamp":       func(p *ProofTrace) { p.Timestamp = "2026-01-02T00:00:00Z" },
		"step name":       func(p *ProofTrace) { p.Steps[0].Name = "sX" },
		"module":          func(p *ProofTrace) { p.Steps[0].Module = "m@2.0" },
		"module checksum": func(p *ProofTrace) { p.Steps[0].ModuleChecksum = "sum-b" },
		"input hash":      func(p *ProofTrace) { p.Steps[0].InputHash = "in2" },
		"output hash":     func(p *ProofTrace) { p.Steps[0].OutputHash = "out2" },
		"extra step":      func(p *ProofTrace) { p.Steps = append(p.Steps, ProofTraceStep{}) },
		"no steps":        func(p *ProofTrace) { p.Steps = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			tr := v2Trace()
			mutate(tr)
			assert.NotEqual(t, base, ComputeChainHashV2(tr))
		})
	}
}

func TestComputeChainHashV2_IgnoresNonInputs(t *testing.T) {
	base := ComputeChainHashV2(v2Trace())
	tr := v2Trace()
	tr.ChainHash = "anything"
	tr.Signature = "vault:v1:sig"
	tr.ChainVersion = ""
	assert.Equal(t, base, ComputeChainHashV2(tr))
}

func TestComputeChainHashV2_LengthPrefixIsUnambiguous(t *testing.T) {
	// With NUL separators these two would encode to the same bytes; length prefixes keep them apart.
	a := v2Trace()
	a.Steps[0].Name, a.Steps[0].Module = "a\x00b", "c"
	b := v2Trace()
	b.Steps[0].Name, b.Steps[0].Module = "a", "b\x00c"
	assert.NotEqual(t, ComputeChainHashV2(a), ComputeChainHashV2(b))

	assert.Equal(t,
		ComputeChainHashV1("wf", "src", []ProofTraceStep{{Name: "a\x00b", Module: "c"}}),
		ComputeChainHashV1("wf", "src", []ProofTraceStep{{Name: "a", Module: "b\x00c"}}),
		"documents why v2 exists: v1 is ambiguous here")
}

func TestComputeChainHash_DispatchesOnVersion(t *testing.T) {
	tr := v2Trace()
	assert.Equal(t, ComputeChainHashV2(tr), ComputeChainHash(tr))

	for _, v := range []string{"", ChainVersionV1} {
		tr.ChainVersion = v
		assert.Equal(t, ComputeChainHashV1(tr.WorkflowID, tr.SourceDigest, tr.Steps), ComputeChainHash(tr), "version %q", v)
	}

	tr.ChainVersion = "v9"
	assert.Empty(t, ComputeChainHash(tr), "an unknown version never matches a declared hash")
}

// newRunTestService builds a service with an "echo" module and a "boom" module whose function
// fails with failErr, plus the given workflow steps.
func newRunTestService(t *testing.T, rec ExecutionRecorder, signer TraceSigner, required bool, failErr error, steps ...string) (*cabinetService, *SetPayload) {
	t.Helper()
	ctx := context.Background()
	modStore := NewMemModuleStore()
	wfStore := NewMemWorkflowStore()

	echo, err := NewModuleDescriptor(ctx, BaseBlock{Name: "echo", Version: "1.0"}, "native", nil, nil, nil)
	require.NoError(t, err)
	echo.NativeImpl = NativeFunctions{"echo": CoreEcho}
	modStore.Put(echo)

	boom, err := NewModuleDescriptor(ctx, BaseBlock{Name: "boom", Version: "1.0"}, "native", nil, nil, nil)
	require.NoError(t, err)
	boom.NativeImpl = NativeFunctions{"fail": func(context.Context, interface{}) (interface{}, error) { return nil, failErr }}
	modStore.Put(boom)

	wf, err := NewWorkflow(ctx, WorkflowIdentity{Version: "1.0"}, WorkflowConfig{Name: "wf.run", Steps: steps}, WorkflowSigning{})
	require.NoError(t, err)
	wfStore.Put(wf)

	svc := &cabinetService{
		modules:          modStore,
		workflows:        wfStore,
		wasmManager:      new(MockWasmManager),
		clock:            func() string { return "2026-01-01T00:00:00Z" },
		recorder:         rec,
		signer:           signer,
		evidenceRequired: required,
	}
	return svc, &SetPayload{WorkflowID: wf.ID(), SourceDigest: "rev-1", Payload: map[string]any{"msg": "hello"}}
}

func TestSetx_FailedRun_IsRecordedWithCompletedSteps(t *testing.T) {
	rec := &captureRecorder{}
	cause := errors.New("make test exit 2")
	svc, p := newRunTestService(t, rec, nil, false, cause,
		"echo@1.0.echo(input) -> a", "boom@1.0.fail(a) -> b")

	resp, err := svc.Setx(context.Background(), p)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, cause, "the cause stays reachable")
	assert.Contains(t, err.Error(), "make test exit 2", "the message is unchanged")

	var failed *ExecutionFailedError
	require.True(t, errors.As(err, &failed))
	require.NotNil(t, failed.Trace)
	assert.Equal(t, TraceStatusFailed, failed.Trace.Status)
	assert.Equal(t, "boom@1.0.fail(a) -> b", failed.Trace.FailedStep)
	require.Len(t, failed.Trace.Steps, 1, "only the completed step is in the chain")
	assert.Equal(t, "echo@1.0", failed.Trace.Steps[0].Module)
	assert.Equal(t, "rev-1", failed.Trace.SourceDigest)
	assert.Equal(t, ChainVersionV2, failed.Trace.ChainVersion)
	assert.Equal(t, ComputeChainHashV2(failed.Trace), failed.Trace.ChainHash)

	require.NotNil(t, failed.Proof)
	assert.True(t, failed.Proof.Persisted)
	require.Len(t, rec.traces, 1, "the failed run reached the recorder")
	assert.Same(t, failed.Trace, rec.traces[0])
}

func TestSetx_FailedFirstStep_IsRecordedWithNoSteps(t *testing.T) {
	rec := &captureRecorder{}
	svc, p := newRunTestService(t, rec, nil, false, errors.New("boom"), "boom@1.0.fail(input) -> b")

	_, err := svc.Setx(context.Background(), p)
	var failed *ExecutionFailedError
	require.True(t, errors.As(err, &failed))
	assert.Empty(t, failed.Trace.Steps)
	assert.Equal(t, "boom@1.0.fail(input) -> b", failed.Trace.FailedStep)
	assert.Len(t, rec.traces, 1)
}

func TestSetx_FailureBeforeDispatch_IsNotRecorded(t *testing.T) {
	rec := &captureRecorder{}
	svc, p := newRunTestService(t, rec, nil, false, nil, "missing@1.0.x(input) -> b")

	_, err := svc.Setx(context.Background(), p)
	require.Error(t, err)
	var failed *ExecutionFailedError
	assert.False(t, errors.As(err, &failed), "nothing ran, so there is nothing to record")
	assert.Empty(t, rec.traces)
}

func TestSetx_FailedRun_KeepsErrorClassification(t *testing.T) {
	svc, p := newRunTestService(t, &captureRecorder{}, nil, false, fmt.Errorf("budget: %w", ErrTimeout),
		"boom@1.0.fail(input) -> b")
	_, err := svc.Setx(context.Background(), p)
	assert.True(t, IsTimeout(err), "IsTimeout sees through ExecutionFailedError")
}

func TestSetx_FailedRun_WithEvidenceRequired_ReturnsTheCause(t *testing.T) {
	cause := errors.New("boom")
	svc, p := newRunTestService(t, &captureRecorder{err: errors.New("vault down")}, nil, true, cause,
		"boom@1.0.fail(input) -> b")
	_, err := svc.Setx(context.Background(), p)
	assert.ErrorIs(t, err, cause)
	assert.False(t, IsEvidenceRequired(err), "the run failed; that is the error the caller needs")
	var failed *ExecutionFailedError
	require.True(t, errors.As(err, &failed))
	assert.False(t, failed.Proof.Persisted)
	assert.Equal(t, ProofErrRecordFailed, failed.Proof.ErrorCode)
}

func TestSetx_SignsTheChainHash(t *testing.T) {
	signer := &fakeSigner{sig: "vault:v1:abc"}
	rec := &captureRecorder{}
	svc, p := newRunTestService(t, rec, signer, false, nil, "echo@1.0.echo(input) -> a")

	resp, err := svc.Setx(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, "vault:v1:abc", resp.Trace.Signature)
	require.Len(t, signer.signed, 1)
	assert.Equal(t, resp.Trace.ChainHash, string(signer.signed[0]), "the signature covers the chain hash")
	require.Len(t, rec.traces, 1)
	assert.Equal(t, "vault:v1:abc", rec.traces[0].Signature, "the recorded trace carries the signature")
}

func TestSetx_SignsFailedRuns(t *testing.T) {
	signer := &fakeSigner{sig: "vault:v1:fail"}
	svc, p := newRunTestService(t, &captureRecorder{}, signer, false, errors.New("boom"), "boom@1.0.fail(input) -> b")
	_, err := svc.Setx(context.Background(), p)
	var failed *ExecutionFailedError
	require.True(t, errors.As(err, &failed))
	assert.Equal(t, "vault:v1:fail", failed.Trace.Signature)
}

func TestSetx_SigningFailure_LeavesTraceUnsigned(t *testing.T) {
	signer := &fakeSigner{sig: "ignored", err: errors.New("vault sealed")}
	svc, p := newRunTestService(t, &captureRecorder{}, signer, false, nil, "echo@1.0.echo(input) -> a")
	resp, err := svc.Setx(context.Background(), p)
	require.NoError(t, err, "signing is best effort: the run itself succeeded")
	assert.Empty(t, resp.Trace.Signature)
	assert.Equal(t, ComputeChainHashV2(resp.Trace), resp.Trace.ChainHash)
}

func TestWithTraceSigner_SetsSigner(t *testing.T) {
	s := &cabinetService{}
	signer := &fakeSigner{}
	WithTraceSigner(signer)(s)
	assert.Same(t, signer, s.signer)
}

func TestExecutionFailedError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("inner")
	e := &ExecutionFailedError{Err: cause}
	assert.Equal(t, "inner", e.Error())
	assert.Same(t, cause, e.Unwrap())
}
