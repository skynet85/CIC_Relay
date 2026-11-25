package main

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ProofVerifyRequest is the request body for POST /v1/proof/verify.
type ProofVerifyRequest struct {
	ProofArtifact *ProofArtifact `json:"proof_artifact"`
}

// ProofVerifyResponse is the response body for POST /v1/proof/verify.
type ProofVerifyResponse struct {
	Valid     bool     `json:"valid"`
	Authentic bool     `json:"authentic"`
	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// proofVerifyHandler handles POST /v1/proof/verify requests: it checks a ProofArtifact against the
// schema contract and recomputes its chain hash (valid), then checks its signature against the
// relay's key (authentic).
func (s *relayServer) proofVerifyHandler(w http.ResponseWriter, r *http.Request) {
	reqID := uuid.New().String()
	logEntry := s.logger.WithFields(logrus.Fields{
		"req-id": reqID,
		"path":   r.URL.Path,
		"method": r.Method,
	})
	logEntry.Info("Handling proof verify request")

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method is allowed")
		return
	}

	limitedReader := io.LimitReader(r.Body, s.config.MaxJSONInputSize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		logEntry.WithField("outcome", "read_error").WithError(err).Error("Failed to read request body")
		writeError(w, http.StatusInternalServerError, "read_error", "Failed to read request")
		return
	}
	defer r.Body.Close()

	if int64(len(body)) > s.config.MaxJSONInputSize {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "Request body too large")
		return
	}

	var req ProofVerifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON: "+err.Error())
		return
	}
	if req.ProofArtifact == nil {
		writeError(w, http.StatusBadRequest, "missing_fields", "proof_artifact is required")
		return
	}

	result := VerifyProofAuthenticity(r.Context(), s.traceVerifier, req.ProofArtifact, VerifyProofArtifact(req.ProofArtifact))

	logEntry.WithFields(logrus.Fields{"outcome": "success", "valid": result.Valid, "authentic": result.Authentic}).Info("Proof verify completed")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ProofVerifyResponse(result))
}
