package main

import (
	"context"
	"testing"

	"centralrelay/core/cabinet"
	"centralrelay/core/modules/schemacompile"
	"centralrelay/pkg/merkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCompileWithoutAssertion registers the native components for trustMode and runs
// cic.schema.compile with a bare schema/version and no source_assertion.
func runCompileWithoutAssertion(t *testing.T, trustMode string) (*cabinet.SetResponse, error) {
	t.Helper()
	ctx := context.Background()
	svc, err := cabinet.NewCabinetService(ctx, cabinet.NewMemSchemaStore(), cabinet.NewMemModuleStore(), cabinet.NewMemWorkflowStore(),
		cabinet.WasmManagerConfig{LRUCacheSize: 10, DefaultTimeoutSeconds: 1})
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close(ctx) })
	require.NoError(t, registerNativeComponents(ctx, svc, &PKIAssets{TrustMode: trustMode}, merkle.BuildContext{SourceRef: "relay-commit"}, nil, &config{}))
	return svc.Setx(ctx, &cabinet.SetPayload{
		WorkflowID: "cic.schema.compile@1.0",
		Payload:    map[string]any{"schema": "pg", "version": "v1"},
	})
}

func TestCompile_Prod_RefusesTheStubPath(t *testing.T) {
	resp, err := runCompileWithoutAssertion(t, TrustModeProd)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "source_assertion is required")
}

func TestCompile_Dev_StubIsMarkedEndToEnd(t *testing.T) {
	resp, err := runCompileWithoutAssertion(t, TrustModeDev)
	require.NoError(t, err)
	signed, ok := resp.Results["signed_artifact"].(map[string]interface{})
	require.True(t, ok, "results: %v", resp.Results)
	assert.Equal(t, true, signed["stub"], "a stub artifact stays marked after signing")
	assert.Equal(t, schemacompile.SourceProvenanceRelay, signed["source_provenance"], "the source fields name the relay, and say so")

	asserted, ok := resp.Results["assert_result"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, schemacompile.AssertionNone, asserted["assertion"])
}

func TestBootstrapTrust_RecordsTheTrustMode(t *testing.T) {
	t.Setenv("CIC_TRUST_MODE", "dev")
	_, assets, err := bootstrapTrust(embeddedFS, newDiscardLogger())
	require.NoError(t, err)
	assert.Equal(t, TrustModeDev, assets.TrustMode)
}
