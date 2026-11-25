package cabinet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"

	"centralrelay/pkg/canonicaljson"
)

// ProofTraceStep records the cryptographic fingerprint of a single workflow step.
//
// ModuleChecksum is the content checksum of the module that ran the step (for a WASM
// module it covers the canonical WASM binary). Module alone is the "name@version"
// label, under which two different binaries can be registered; the checksum names
// the artifact. It is bound by the v2 chain hash and ignored by v1.
type ProofTraceStep struct {
	Name           string `json:"name"`
	Module         string `json:"module"`
	ModuleChecksum string `json:"module_checksum,omitempty"`
	InputHash      string `json:"input_hash"`
	OutputHash     string `json:"output_hash"`
}

// Chain format versions carried in ProofTrace.ChainVersion. An empty version means v1.
const (
	// ChainVersionV1 is the original format (ComputeChainHashV1): source, workflow and per-step
	// name/module/input/output, NUL-separated. It binds neither the module binary, the timestamp
	// nor the outcome of the run.
	ChainVersionV1 = "v1"
	// ChainVersionV2 is ComputeChainHashV2: length-prefixed fields that also bind the module
	// checksum of every step, the timestamp and the outcome (status, failed step).
	ChainVersionV2 = "v2"
)

// Outcomes of an execution, carried in ProofTrace.Status (bound by the v2 chain hash).
const (
	// TraceStatusCompleted: every step ran.
	TraceStatusCompleted = "completed"
	// TraceStatusFailed: a step failed after the run had started; Steps holds the steps that
	// completed and FailedStep names the one that did not. Earlier steps may have had side effects.
	TraceStatusFailed = "failed"
)

// ProofTrace is the immutable audit record of a completed workflow execution.
// Every field is deterministic and canonicalizable; no clock or RNG side-effects
// are introduced here — the Timestamp must be injected by the caller.
//
// SourceDigest anchors the chain to the source revision. It is injected by the caller
// (e.g. git HEAD commit hash or BuildID) and becomes the first input of ChainHash,
// making the hash-chain continuous from source to output.
//
// ChainVersion names the chain hash format (empty = v1). Status and FailedStep record the
// outcome: a failed run is recorded too, with the steps that completed. Signature, when
// present, is the relay's signature over ChainHash (TraceSigner); it is not part of the
// hash, and it is what turns a well-formed trace into one whose origin can be checked.
type ProofTrace struct {
	WorkflowID   string           `json:"workflow_id"`
	SourceDigest string           `json:"source_digest,omitempty"`
	ChainVersion string           `json:"chain_version,omitempty"`
	Status       string           `json:"status,omitempty"`
	FailedStep   string           `json:"failed_step,omitempty"`
	Steps        []ProofTraceStep `json:"steps"`
	ChainHash    string           `json:"chain_hash"`
	Timestamp    string           `json:"timestamp"`
	Signature    string           `json:"signature,omitempty"`
}

// TraceSigner signs the chain hash of a ProofTrace with the relay's key (for example a
// Vault Transit key: crypto.CryptoService satisfies it). The key never leaves the backend.
type TraceSigner interface {
	Sign(ctx context.Context, data []byte) (string, error)
}

// TraceVerifier checks a ProofTrace signature against the relay's key.
type TraceVerifier interface {
	Verify(ctx context.Context, data []byte, signature string) (bool, error)
}

// ProofTraceStepFromActuation projects an http-executor actuation's non-secret
// audit facts (feature-009, carried across the Rust↔Go FFI boundary by run_flow)
// into a ProofTraceStep, so a capability actuation folds into the same
// hash-chained ProofTrace as native and WASM steps. The request/response body
// SHA-256 digests become the step's input/output hashes; the step name is the
// caller's traceID, or "<method> <host>" when no trace id was supplied. It
// carries only digests — never the credential or any body contents.
func ProofTraceStepFromActuation(traceID, method, host, requestBodySHA256, responseBodySHA256 string) ProofTraceStep {
	name := traceID
	if name == "" {
		name = method + " " + host
	}
	return ProofTraceStep{
		Name:       name,
		Module:     "http-executor",
		InputHash:  requestBodySHA256,
		OutputHash: responseBodySHA256,
	}
}

// ActuationProof is the durable, recordable proof of one http-executor
// actuation (feature-009): the Go-side single-step ProofTrace (with its
// ChainHash) plus the Rust-side tamper-evident record_hash anchor carried across
// the FFI seam. Handed to an ExecutionRecorder, it is persisted as a
// Vault-signed Git commit (WorkflowRecorder → GitStateRecorder), so an actuation
// becomes durable, cryptographically anchored provenance — not just an in-memory
// fact. Both chains travel together: the Go ProofTrace ChainHash and the Rust
// ChainedEntry record_hash.
type ActuationProof struct {
	ProofTrace *ProofTrace `json:"proof_trace"`
	// RecordHash is the Rust-side ChainedEntry anchor (hex SHA-256), empty if the
	// actuation carried no audit chain.
	RecordHash string `json:"record_hash"`
}

// ProofFromActuation wraps a single actuation step into an ActuationProof: a
// complete, recordable single-step ProofTrace (anchored to sourceDigest, with
// the ChainHash and an injected timestamp) plus the Rust record_hash anchor.
// Build step with ProofTraceStepFromActuation. Hand the result to an
// ExecutionRecorder to persist it durably.
func ProofFromActuation(workflowID, sourceDigest, timestamp, recordHash string, step ProofTraceStep) ActuationProof {
	steps := []ProofTraceStep{step}
	return ActuationProof{
		ProofTrace: &ProofTrace{
			WorkflowID:   workflowID,
			SourceDigest: sourceDigest,
			Steps:        steps,
			ChainHash:    ComputeChainHashV1(workflowID, sourceDigest, steps),
			Timestamp:    timestamp,
		},
		RecordHash: recordHash,
	}
}

// hashValue returns the hex-encoded SHA-256 of the canonical JSON representation of v.
func hashValue(v interface{}) (string, error) {
	b, err := canonicaljson.ToJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ComputeChainHashV1 returns SHA-256 over the full execution identity:
//
//	"CICCHAINv1" \x00 sourceDigest \x00 workflowID \x00 [per step: name \x00 module \x00 inputHash \x00 outputHash \x00]
//
// The "CICCHAINv1" domain prefix:
//   - Distinguishes chain hashes from Merkle-root hashes or leaf hashes produced
//     elsewhere in this system (domain separation).
//   - Makes the format versioned: a future format change uses "CICCHAINv2" and the
//     two are unambiguously different even with identical field contents.
//
// \x00 separators prevent hash collisions between adjacent variable-length fields.
// sourceDigest anchors the chain to the source revision; pass "" when not available.
// workflowID binds the hash to the exact workflow definition that was executed.
// InputHash and step Name are included so that two different workflows producing
// the same outputs cannot share the same ChainHash.
func ComputeChainHashV1(workflowID, sourceDigest string, steps []ProofTraceStep) string {
	var sb strings.Builder
	sb.WriteString("CICCHAINv1") // domain prefix — see comment above
	sb.WriteByte(0)
	sb.WriteString(sourceDigest)
	sb.WriteByte(0)
	sb.WriteString(workflowID)
	sb.WriteByte(0)
	for _, s := range steps {
		sb.WriteString(s.Name)
		sb.WriteByte(0)
		sb.WriteString(s.Module)
		sb.WriteByte(0)
		sb.WriteString(s.InputHash)
		sb.WriteByte(0)
		sb.WriteString(s.OutputHash)
		sb.WriteByte(0)
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// ComputeChainHashV2 returns the v2 chain hash of t: SHA-256 over
//
//	"CICCHAINv2" ‖ f(source_digest) ‖ f(workflow_id) ‖ f(status) ‖ f(failed_step) ‖ f(timestamp) ‖ f(len(steps))
//	‖ per step: f(name) ‖ f(module) ‖ f(module_checksum) ‖ f(input_hash) ‖ f(output_hash)
//
// where f(x) is the 8-byte big-endian length of x followed by x. Length prefixes make the
// encoding unambiguous for any field content (v1's NUL separators are ambiguous when a field
// itself contains a NUL byte). Compared with v1 it also binds the module checksum of every
// step, the timestamp and the outcome of the run. ChainHash, ChainVersion and Signature are
// not inputs.
func ComputeChainHashV2(t *ProofTrace) string {
	h := sha256.New()
	h.Write([]byte("CICCHAINv2"))
	field := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	field(t.SourceDigest)
	field(t.WorkflowID)
	field(t.Status)
	field(t.FailedStep)
	field(t.Timestamp)
	field(strconv.Itoa(len(t.Steps)))
	for _, s := range t.Steps {
		field(s.Name)
		field(s.Module)
		field(s.ModuleChecksum)
		field(s.InputHash)
		field(s.OutputHash)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeChainHash returns the chain hash of t in the format its ChainVersion names: v2
// (ComputeChainHashV2) for "v2", v1 (ComputeChainHashV1) for "" and "v1". It returns "" for an
// unknown version, which never equals a declared hash, so a verifier rejects it.
func ComputeChainHash(t *ProofTrace) string {
	switch t.ChainVersion {
	case ChainVersionV2:
		return ComputeChainHashV2(t)
	case "", ChainVersionV1:
		return ComputeChainHashV1(t.WorkflowID, t.SourceDigest, t.Steps)
	default:
		return ""
	}
}
