package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"centralrelay/core/cabinet"
	"centralrelay/core/nexus/iac"
	"centralrelay/core/nexus/types"
)

func silentActivatorLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(&bytes.Buffer{})
	return l
}

func makeResource(schemaName, schemaVersion string, spec map[string]any) types.ResourceSpec {
	return types.ResourceSpec{
		Meta:      types.ResourceMeta{Name: "res-test"},
		SchemaRef: types.SchemaRef{Name: schemaName, Version: schemaVersion},
		Spec:      spec,
		State:     types.ResourceState{Desired: "present"},
	}
}

// allowLookups lets API.Set's request validation (workflow and module lookups) pass.
func allowLookups(mc *mockCabinetService) {
	mc.On("GetWorkflow", mock.Anything).Return(&cabinet.Workflow{}, nil)
	mc.On("GetModule", mock.Anything).Return(&cabinet.ModuleDescriptor{}, nil)
}

func TestCabinetActivator_Activate_Success(t *testing.T) {
	mc := new(mockCabinetService)
	allowLookups(mc)
	mc.On("Setx", mock.Anything, mock.MatchedBy(func(p *cabinet.SetPayload) bool {
		return p.WorkflowID == "core.test@1.0" &&
			len(p.Modules) == 1 &&
			string(p.Modules[0]) == "core.test@1.0"
	})).Return(&cabinet.SetResponse{
		Results: map[string]any{"status": "ok"},
		Trace:   &cabinet.ProofTrace{ChainHash: "abc123"},
	}, nil)

	act := NewCabinetActivator(mc, silentActivatorLogger())
	res := makeResource("core.test", "1.0", map[string]any{"key": "value"})

	err := act.Activate(context.Background(), "svc-a", res)
	require.NoError(t, err)
	mc.AssertExpectations(t)
}

func TestCabinetActivator_Activate_SetxError(t *testing.T) {
	mc := new(mockCabinetService)
	allowLookups(mc)
	mc.On("Setx", mock.Anything, mock.Anything).Return(nil, errors.New("workflow not found"))

	act := NewCabinetActivator(mc, silentActivatorLogger())
	res := makeResource("core.test", "1.0", nil)

	err := act.Activate(context.Background(), "svc-a", res)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow not found")
	assert.Contains(t, err.Error(), "core.test@1.0")
}

func TestCabinetActivator_Activate_NilTrace(t *testing.T) {
	mc := new(mockCabinetService)
	allowLookups(mc)
	mc.On("Setx", mock.Anything, mock.Anything).Return(&cabinet.SetResponse{
		Results: map[string]any{},
		Trace:   nil,
	}, nil)

	act := NewCabinetActivator(mc, silentActivatorLogger())
	res := makeResource("core.test", "2.0", nil)

	err := act.Activate(context.Background(), "svc-b", res)
	require.NoError(t, err)
}

func TestCabinetActivator_Activate_PayloadMapping(t *testing.T) {
	var capturedPayload *cabinet.SetPayload
	mc := new(mockCabinetService)
	allowLookups(mc)
	mc.On("Setx", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedPayload = args.Get(1).(*cabinet.SetPayload)
	}).Return(&cabinet.SetResponse{}, nil)

	act := NewCabinetActivator(mc, silentActivatorLogger())
	spec := map[string]any{"host": "db.local", "port": 5432}
	res := makeResource("postgres.instance", "v2", spec)

	require.NoError(t, act.Activate(context.Background(), "svc-db", res))

	require.NotNil(t, capturedPayload)
	assert.Equal(t, "postgres.instance@v2", capturedPayload.WorkflowID)
	assert.Equal(t, spec, capturedPayload.Payload)

	want, err := iac.SpecDigest(spec)
	require.NoError(t, err)
	assert.Equal(t, want, capturedPayload.SourceDigest, "the trace is anchored to the declared spec")
	assert.NotEmpty(t, capturedPayload.SourceDigest)
}

func TestCabinetActivator_Activate_ValidatesThroughAPISet(t *testing.T) {
	mc := new(mockCabinetService)
	mc.On("GetWorkflow", mock.Anything).Return(nil, cabinet.ErrNotFound)

	act := NewCabinetActivator(mc, silentActivatorLogger())
	err := act.Activate(context.Background(), "svc-a", makeResource("missing.wf", "1.0", nil))
	require.Error(t, err)
	assert.True(t, cabinet.IsNotFound(err), "request validation runs before execution")
	mc.AssertNotCalled(t, "Setx", mock.Anything, mock.Anything)
}

func TestCabinetActivator_Activate_SameSpecSameAnchor(t *testing.T) {
	var got []string
	mc := new(mockCabinetService)
	allowLookups(mc)
	mc.On("Setx", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		got = append(got, args.Get(1).(*cabinet.SetPayload).SourceDigest)
	}).Return(&cabinet.SetResponse{}, nil)

	act := NewCabinetActivator(mc, silentActivatorLogger())
	require.NoError(t, act.Activate(context.Background(), "s", makeResource("x", "1", map[string]any{"cpu": 4})))
	require.NoError(t, act.Activate(context.Background(), "s", makeResource("x", "1", map[string]any{"cpu": 4.0})))
	require.NoError(t, act.Activate(context.Background(), "s", makeResource("x", "1", map[string]any{"cpu": 8})))
	require.Len(t, got, 3)
	assert.Equal(t, got[0], got[1], "4 and 4.0 declare the same intent")
	assert.NotEqual(t, got[0], got[2], "a different spec is a different anchor")
}

func TestCabinetActivator_Activate_UndigestableSpec(t *testing.T) {
	mc := new(mockCabinetService)
	act := NewCabinetActivator(mc, silentActivatorLogger())
	err := act.Activate(context.Background(), "svc-a", makeResource("x", "1", map[string]any{"bad": make(chan int)}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "digest of the declared spec")
	mc.AssertNotCalled(t, "Setx", mock.Anything, mock.Anything)
}
