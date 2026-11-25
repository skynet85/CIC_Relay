package schemacompile_test

import (
	"context"
	"testing"

	"centralrelay/core/modules/schemacompile"
	"centralrelay/pkg/merkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssertSource_StubMode_IsMarkedAsNoAssertion(t *testing.T) {
	out, err := schemacompile.NewAssertSourceFunc(nil)(context.Background(), map[string]interface{}{"schema": "s", "version": "1.0"})
	require.NoError(t, err)
	assert.Equal(t, schemacompile.AssertionNone, out.(map[string]interface{})["assertion"])

	out, err = schemacompile.AssertSource(context.Background(), map[string]interface{}{"schema": "s", "version": "1.0"})
	require.NoError(t, err)
	assert.Equal(t, schemacompile.AssertionNone, out.(map[string]interface{})["assertion"], "the legacy entry point marks it too")
}

func TestStrictAssertSource_RejectsMissingAssertion(t *testing.T) {
	_, err := schemacompile.NewStrictAssertSourceFunc(nil)(context.Background(), map[string]interface{}{"schema": "s", "version": "1.0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source_assertion is required")
}

func TestStrictAssertSource_AcceptsAnAssertion(t *testing.T) {
	out, err := schemacompile.NewStrictAssertSourceFunc(nil)(context.Background(), map[string]interface{}{
		"source_assertion": minimalAssertion("test.schema", "1.0"),
	})
	require.NoError(t, err)
	m := out.(map[string]interface{})
	assert.Equal(t, true, m["asserted"])
	assert.NotContains(t, m, "assertion", "a real assertion carries no stub marker")
}

func TestBuildSchema_StubOutputIsMarked(t *testing.T) {
	out, err := schemacompile.BuildSchema(context.Background(), map[string]interface{}{"schema": "pg", "version": "v1"})
	require.NoError(t, err)
	assert.Equal(t, true, out.(map[string]interface{})["stub"])
}

func TestNewBuildSchemaFunc(t *testing.T) {
	asserted := map[string]interface{}{
		"schema": "pg", "version": "v1",
		"metadata": map[string]interface{}{"name": "pg", "version": "v1"},
		"raw_yaml": "metadata:\n  name: pg\n",
	}

	t.Run("stub disabled rejects an input with no asserted artifact", func(t *testing.T) {
		_, err := schemacompile.NewBuildSchemaFunc(false)(context.Background(), map[string]interface{}{"schema": "pg", "version": "v1"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stub mode is disabled")
	})
	t.Run("stub disabled still builds an asserted artifact", func(t *testing.T) {
		out, err := schemacompile.NewBuildSchemaFunc(false)(context.Background(), asserted)
		require.NoError(t, err)
		m := out.(map[string]interface{})
		assert.Equal(t, "metadata:\n  name: pg\n", m["raw_artifact"])
		assert.NotContains(t, m, "stub")
	})
	t.Run("stub allowed behaves like BuildSchema", func(t *testing.T) {
		out, err := schemacompile.NewBuildSchemaFunc(true)(context.Background(), map[string]interface{}{"schema": "pg", "version": "v1"})
		require.NoError(t, err)
		assert.Equal(t, true, out.(map[string]interface{})["stub"])
	})
}

func TestSignArtifact_CarriesStubAndSourceProvenance(t *testing.T) {
	bctx := merkle.BuildContext{SourceRef: "relay-commit", SourceTreeDigest: "relay-tree"}
	sign := schemacompile.NewSignArtifactFunc(bctx, nil)

	t.Run("no repository: the source fields are the relay's and say so", func(t *testing.T) {
		out, err := sign(context.Background(), map[string]interface{}{"raw_artifact": "x", "stub": true})
		require.NoError(t, err)
		m := out.(map[string]interface{})
		assert.Equal(t, schemacompile.SourceProvenanceRelay, m["source_provenance"])
		assert.Equal(t, "relay-commit", m["source_ref"])
		assert.Equal(t, true, m["stub"], "a signed stub stays recognisable")
	})
	t.Run("repository run", func(t *testing.T) {
		out, err := sign(context.Background(), map[string]interface{}{"raw_artifact": "x", "source_ref": "repo-commit", "source_tree_digest": "repo-tree"})
		require.NoError(t, err)
		m := out.(map[string]interface{})
		assert.Equal(t, schemacompile.SourceProvenanceRepository, m["source_provenance"])
		assert.Equal(t, "repo-commit", m["source_ref"])
		assert.NotContains(t, m, "stub")
	})
	t.Run("a partial repository source still counts as the repository's", func(t *testing.T) {
		out, err := sign(context.Background(), map[string]interface{}{"raw_artifact": "x", "source_ref": "repo-commit"})
		require.NoError(t, err)
		assert.Equal(t, schemacompile.SourceProvenanceRepository, out.(map[string]interface{})["source_provenance"])
		out, err = sign(context.Background(), map[string]interface{}{"raw_artifact": "x", "source_tree_digest": "repo-tree"})
		require.NoError(t, err)
		assert.Equal(t, schemacompile.SourceProvenanceRepository, out.(map[string]interface{})["source_provenance"])
	})
	t.Run("stub false is not carried", func(t *testing.T) {
		out, err := sign(context.Background(), map[string]interface{}{"raw_artifact": "x", "stub": false})
		require.NoError(t, err)
		assert.NotContains(t, out.(map[string]interface{}), "stub")
	})
}
