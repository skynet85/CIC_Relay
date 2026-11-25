package main

import (
	"context"
	"encoding/json"
	"fmt"

	"centralrelay/core/cabinet"
)

// ProofArtifact is the unified proof record produced by every CIC-Relay execution.
// It implements the proof_artifact@1.0 schema contract.
type ProofArtifact struct {
	WorkflowID   string               `json:"workflow_id"`
	SourceDigest string               `json:"source_digest"`
	ChainVersion string               `json:"chain_version,omitempty"`
	Status       string               `json:"status,omitempty"`
	FailedStep   string               `json:"failed_step,omitempty"`
	ChainHash    string               `json:"chain_hash"`
	Steps        []ProofArtifactStep  `json:"steps"`
	Timestamp    string               `json:"timestamp"`
	Signature    string               `json:"signature,omitempty"`
	PoSEResult   string               `json:"pose_result,omitempty"`
	CommitRecord *ProofArtifactCommit `json:"commit_record,omitempty"`
}

// ProofArtifactStep mirrors cabinet.ProofTraceStep for the verifier.
type ProofArtifactStep struct {
	Name           string `json:"name"`
	Module         string `json:"module"`
	ModuleChecksum string `json:"module_checksum,omitempty"`
	InputHash      string `json:"input_hash"`
	OutputHash     string `json:"output_hash"`
}

// ProofArtifactCommit holds the state commit record appended after PoSE verification.
type ProofArtifactCommit struct {
	ID        string `json:"id"`
	TraceHead string `json:"trace_head"`
	PoSERoot  string `json:"pose_root"`
	Actor     string `json:"actor,omitempty"`
}

// VerifyResult is the output of VerifyProofArtifact (and of the authenticity check on top of it).
//
// Valid means the artifact is well formed and its chain hash recomputes: integrity. It does
// not say who produced it — anyone can compute a SHA-256 chain. Authentic means, in addition,
// that the artifact's signature over the chain hash verifies against the relay's key.
type VerifyResult struct {
	Valid     bool     `json:"valid"`
	Authentic bool     `json:"authentic"`
	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// VerifyProofArtifact validates a ProofArtifact against the proof_artifact@1.0 schema contract.
//
// Checks performed:
//  1. Required fields present (workflow_id, source_digest, chain_hash, steps, timestamp).
//  2. chain_hash recomputed and verified against the artifact's declared value.
//  3. Per-step: name, module, input_hash, output_hash all non-empty.
//  4. pose_result value is one of: VERIFIED | DRIFT | SKIPPED (when present).
//  5. commit_record.id == chain_hash when commit_record is present.
func VerifyProofArtifact(a *ProofArtifact) VerifyResult {
	var errs, warns []string

	// 1. Required fields
	if a.WorkflowID == "" {
		errs = append(errs, "workflow_id is required")
	}
	if a.ChainHash == "" {
		errs = append(errs, "chain_hash is required")
	}
	if a.Timestamp == "" {
		errs = append(errs, "timestamp is required")
	}
	// An unset source_digest and the "unknown" sentinel mean the same thing: the
	// chain identifies no source revision. Checking only for emptiness let the
	// sentinel through silently, so a trace that was in fact unanchored verified
	// with no warning at all.
	if a.SourceDigest == "" || a.SourceDigest == "unknown" {
		warns = append(warns, "source_digest is empty or unknown — chain is not anchored to a source revision")
	}

	// 2. chain_hash recomputation, in the format the artifact declares.
	switch a.ChainVersion {
	case "", cabinet.ChainVersionV1:
		warns = append(warns, "chain_version v1: the module binary, the timestamp and the outcome are not bound by the chain hash")
	case cabinet.ChainVersionV2:
	default:
		errs = append(errs, fmt.Sprintf("chain_version %q is not supported (v1, v2)", a.ChainVersion))
	}
	if a.WorkflowID != "" && a.ChainHash != "" {
		expected := cabinet.ComputeChainHash(a.toTrace())
		if expected != a.ChainHash {
			errs = append(errs, fmt.Sprintf(
				"chain_hash mismatch: declared=%s recomputed=%s", a.ChainHash, expected,
			))
		}
	}

	// 2b. outcome
	switch a.Status {
	case "", cabinet.TraceStatusCompleted:
		if a.FailedStep != "" {
			errs = append(errs, "failed_step is set but status is not \"failed\"")
		}
	case cabinet.TraceStatusFailed:
		if a.FailedStep == "" {
			errs = append(errs, "status \"failed\" requires failed_step")
		}
		warns = append(warns, "status is \"failed\": the run did not complete; the steps listed did run")
	default:
		errs = append(errs, fmt.Sprintf("status must be completed | failed, got %q", a.Status))
	}

	// 3. Per-step validation
	for i, s := range a.Steps {
		prefix := fmt.Sprintf("steps[%d]", i)
		if s.Name == "" {
			errs = append(errs, prefix+".name is required")
		}
		if s.Module == "" {
			errs = append(errs, prefix+".module is required")
		}
		if s.InputHash == "" {
			errs = append(errs, prefix+".input_hash is required")
		}
		if s.OutputHash == "" {
			errs = append(errs, prefix+".output_hash is required")
		}
	}

	// 4. pose_result enum
	if a.PoSEResult != "" {
		switch a.PoSEResult {
		case "VERIFIED", "DRIFT", "SKIPPED":
		default:
			errs = append(errs, fmt.Sprintf(
				"pose_result must be VERIFIED | DRIFT | SKIPPED, got %q", a.PoSEResult,
			))
		}
	}

	// 5. commit_record consistency
	if a.CommitRecord != nil {
		if a.CommitRecord.ID != a.ChainHash {
			errs = append(errs, fmt.Sprintf(
				"commit_record.id must equal chain_hash: got %q, want %q",
				a.CommitRecord.ID, a.ChainHash,
			))
		}
		if a.PoSEResult != "VERIFIED" {
			warns = append(warns, "commit_record present but pose_result is not VERIFIED")
		}
	}

	return VerifyResult{
		Valid:    len(errs) == 0,
		Errors:   errs,
		Warnings: warns,
	}
}

// ProofArtifactFromTrace converts a cabinet.ProofTrace to a ProofArtifact.
func ProofArtifactFromTrace(t *cabinet.ProofTrace) *ProofArtifact {
	steps := make([]ProofArtifactStep, len(t.Steps))
	for i, s := range t.Steps {
		steps[i] = ProofArtifactStep{
			Name:           s.Name,
			Module:         s.Module,
			ModuleChecksum: s.ModuleChecksum,
			InputHash:      s.InputHash,
			OutputHash:     s.OutputHash,
		}
	}
	return &ProofArtifact{
		WorkflowID:   t.WorkflowID,
		SourceDigest: t.SourceDigest,
		ChainVersion: t.ChainVersion,
		Status:       t.Status,
		FailedStep:   t.FailedStep,
		ChainHash:    t.ChainHash,
		Steps:        steps,
		Timestamp:    t.Timestamp,
		Signature:    t.Signature,
	}
}

// toTrace is the inverse of ProofArtifactFromTrace: the cabinet.ProofTrace the artifact describes.
func (a *ProofArtifact) toTrace() *cabinet.ProofTrace {
	steps := make([]cabinet.ProofTraceStep, len(a.Steps))
	for i, s := range a.Steps {
		steps[i] = cabinet.ProofTraceStep{
			Name:           s.Name,
			Module:         s.Module,
			ModuleChecksum: s.ModuleChecksum,
			InputHash:      s.InputHash,
			OutputHash:     s.OutputHash,
		}
	}
	return &cabinet.ProofTrace{
		WorkflowID:   a.WorkflowID,
		SourceDigest: a.SourceDigest,
		ChainVersion: a.ChainVersion,
		Status:       a.Status,
		FailedStep:   a.FailedStep,
		Steps:        steps,
		ChainHash:    a.ChainHash,
		Timestamp:    a.Timestamp,
		Signature:    a.Signature,
	}
}

// VerifyProofAuthenticity adds the origin check to an integrity result r of a: it sets
// r.Authentic when a carries a signature over its chain hash that verifies against the relay's
// key (verifier). A signature that does not verify makes the artifact invalid: the chain was
// altered or was not signed by this relay. An unsigned artifact, a relay with no verifier, or a
// verifier backend error leave Authentic false with a warning: integrity only, origin not proven.
func VerifyProofAuthenticity(ctx context.Context, verifier cabinet.TraceVerifier, a *ProofArtifact, r VerifyResult) VerifyResult {
	r.Authentic = false
	if !r.Valid {
		return r
	}
	if a.Signature == "" {
		r.Warnings = append(r.Warnings, "unsigned: integrity verified, origin not proven")
		return r
	}
	if verifier == nil {
		r.Warnings = append(r.Warnings, "signature present but this relay has no verification key configured: origin not checked")
		return r
	}
	ok, err := verifier.Verify(ctx, []byte(a.ChainHash), a.Signature)
	if err != nil {
		r.Warnings = append(r.Warnings, "signature could not be checked (verification backend error): origin not proven")
		return r
	}
	if !ok {
		r.Valid = false
		r.Errors = append(r.Errors, "signature does not verify against the relay key")
		return r
	}
	r.Authentic = true
	return r
}

// MarshalProofArtifact serializes a ProofArtifact to canonical JSON format for transport or storage.
func MarshalProofArtifact(a *ProofArtifact) ([]byte, error) {
	return json.Marshal(a)
}
