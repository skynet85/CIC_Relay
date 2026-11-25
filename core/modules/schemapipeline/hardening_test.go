package schemapipeline_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"centralrelay/core/modules/schemapipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startInput is a valid cic.pipeline.start input, adjusted by the caller.
func startInput(kv ...string) map[string]interface{} {
	m := map[string]interface{}{"repo_url": "https://git.example.com/schemas.git", "branch": "main", "schema": "pg", "version": "v1.0.0"}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// sentinelDir is a build dir with a file in it, to prove start did not delete it.
func sentinelDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keep"), []byte("x"), 0o600))
	return dir
}

func assertUntouched(t *testing.T, dir string, mr *mockRunner) {
	t.Helper()
	assert.Empty(t, mr.seen, "no command may run before the request is validated")
	_, err := os.Stat(filepath.Join(dir, "keep"))
	assert.NoError(t, err, "the build dir must not be deleted for a refused request")
}

func TestStart_RejectsOptionLikeAndOddArguments(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"branch as option":    startInput("branch", "--upload-pack=touch /tmp/x"),
		"branch with ..":      startInput("branch", "a/../b"),
		"commit as option":    startInput("commit", "-x"),
		"commit with space":   startInput("commit", "abc def"),
		"repo_url as option":  startInput("repo_url", "--upload-pack=touch /tmp/x"),
		"repo_url ext::":      startInput("repo_url", "ext::sh -c touch% /tmp/x"),
		"repo_url plain http": startInput("repo_url", "http://git.example.com/x.git"),
		"repo_url bare path":  startInput("repo_url", "/srv/repo"),
		"repo_url host:path":  startInput("repo_url", "host:path"),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			dir := sentinelDir(t)
			mr := &mockRunner{}
			cfg := &schemapipeline.PipelineConfig{BuildDir: dir, Runner: mr}
			_, err := cfg.NewStartFunc()(context.Background(), in)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not allowed")
			assertUntouched(t, dir, mr)
		})
	}
}

func TestStart_AcceptsTheSupportedURLForms(t *testing.T) {
	for _, u := range []string{
		"https://git.example.com/x.git", "ssh://git@example.com/x.git", "git://example.com/x.git",
		"file:///src/x", "git@github.com:owner/repo.git",
	} {
		t.Run(u, func(t *testing.T) {
			mr := &mockRunner{}
			mr.expectNext("git clone", "", 0)
			cfg := &schemapipeline.PipelineConfig{BuildDir: t.TempDir(), Runner: mr}
			_, _ = cfg.NewStartFunc()(context.Background(), startInput("repo_url", u))
			require.NotEmpty(t, mr.seen, "%s must reach git", u)
			assert.Contains(t, mr.seen[0], "-- "+u)
		})
	}
}

func TestStart_RefusesUnsafeBuildDirs(t *testing.T) {
	for _, dir := range []string{"/", "relative/dir", "/tmp/../"} {
		t.Run(dir, func(t *testing.T) {
			mr := &mockRunner{}
			cfg := &schemapipeline.PipelineConfig{BuildDir: dir, Runner: mr}
			_, err := cfg.NewStartFunc()(context.Background(), startInput())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must be an absolute path other than /")
			assert.Empty(t, mr.seen)
		})
	}
}

func TestStart_RestrictOverrides(t *testing.T) {
	t.Run("a different build_dir is refused before anything runs", func(t *testing.T) {
		dir := sentinelDir(t)
		mr := &mockRunner{}
		cfg := &schemapipeline.PipelineConfig{BuildDir: dir, RestrictOverrides: true, Runner: mr}
		_, err := cfg.NewStartFunc()(context.Background(), startInput("build_dir", t.TempDir()))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build_dir is set by the operator")
		assertUntouched(t, dir, mr)
	})
	t.Run("a different builder_container is refused before anything runs", func(t *testing.T) {
		dir := sentinelDir(t)
		mr := &mockRunner{}
		cfg := &schemapipeline.PipelineConfig{BuildDir: dir, BuilderContainer: "cic-builder", RestrictOverrides: true, Runner: mr}
		_, err := cfg.NewStartFunc()(context.Background(), startInput("builder_container", "postgres"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "builder_container is set by the operator")
		assertUntouched(t, dir, mr)
	})
	t.Run("the configured values themselves pass", func(t *testing.T) {
		dir := t.TempDir()
		mr := &mockRunner{}
		mr.expectNext("git clone", "", 0)
		cfg := &schemapipeline.PipelineConfig{BuildDir: dir, BuilderContainer: "cic-builder", RestrictOverrides: true, Runner: mr}
		_, _ = cfg.NewStartFunc()(context.Background(), startInput("build_dir", dir, "builder_container", "cic-builder"))
		assert.NotEmpty(t, mr.seen, "same-as-configured values are not overrides")
	})
	t.Run("without restriction an override is still honoured", func(t *testing.T) {
		other := t.TempDir()
		mr := &mockRunner{}
		mr.expectNext("git clone", "", 0)
		cfg := &schemapipeline.PipelineConfig{BuildDir: t.TempDir(), Runner: mr}
		_, _ = cfg.NewStartFunc()(context.Background(), startInput("build_dir", other))
		require.NotEmpty(t, mr.seen)
		assert.Contains(t, mr.seen[0], other)
	})
}

func TestMakeSteps_RefuseOptionLikeTargetsAndContainerOverrides(t *testing.T) {
	t.Run("make target as option", func(t *testing.T) {
		mr := &mockRunner{}
		cfg := &schemapipeline.PipelineConfig{BuildDir: t.TempDir(), BuilderContainer: "c", Runner: mr}
		_, err := cfg.NewRepoBuildFunc()(context.Background(), map[string]interface{}{
			"make_target": "--eval=$(shell id)", "artifact_output": "out.bin",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "make_target")
		assert.Empty(t, mr.seen)
	})
	t.Run("container override under restriction", func(t *testing.T) {
		mr := &mockRunner{}
		cfg := &schemapipeline.PipelineConfig{BuildDir: t.TempDir(), BuilderContainer: "c", RestrictOverrides: true, Runner: mr}
		_, err := cfg.NewTestFunc()(context.Background(), map[string]interface{}{"builder_container": "other"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "builder_container is set by the operator")
		assert.Empty(t, mr.seen)
	})
	t.Run("repo build_dir override under restriction", func(t *testing.T) {
		mr := &mockRunner{}
		cfg := &schemapipeline.PipelineConfig{BuildDir: t.TempDir(), BuilderContainer: "c", RestrictOverrides: true, Runner: mr}
		_, err := cfg.NewRepoBuildFunc()(context.Background(), map[string]interface{}{
			"artifact_output": "out.bin", "build_dir": t.TempDir(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build_dir is set by the operator")
		assert.Empty(t, mr.seen)
	})
}

func TestRelease_RefusesUnsafeSchemaVersionAndOverrides(t *testing.T) {
	base := func(kv ...string) map[string]interface{} {
		m := map[string]interface{}{"schema": "pg", "version": "v1.2.3"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cases := map[string]struct {
		in       map[string]interface{}
		restrict bool
		want     string
	}{
		"schema path traversal": {base("schema", "../../etc/passwd"), false, "schema"},
		"schema as option":      {base("schema", "-x"), false, "schema"},
		"version with space":    {base("version", "1.0 -f evil"), false, "version"},
		"container override":    {base("builder_container", "other"), true, "builder_container is set by the operator"},
		"build_dir override":    {base("build_dir", "/elsewhere"), true, "build_dir is set by the operator"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mr := &mockRunner{}
			cfg := &schemapipeline.PipelineConfig{BuildDir: t.TempDir(), BuilderContainer: "c", RestrictOverrides: tc.restrict, Runner: mr}
			_, err := cfg.NewReleaseFunc()(context.Background(), tc.in)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Empty(t, mr.seen)
		})
	}
}
