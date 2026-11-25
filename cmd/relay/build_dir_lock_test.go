package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLockBuildDir_SerializesRunsOnOneDir(t *testing.T) {
	const runs = 8
	var inside, maxInside int32
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := lockBuildDir("/build/serial-test")
			defer unlock()
			n := atomic.AddInt32(&inside, 1)
			for {
				m := atomic.LoadInt32(&maxInside)
				if n <= m || atomic.CompareAndSwapInt32(&maxInside, m, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt32(&inside, -1)
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), maxInside, "two runs on one build dir never overlap")
}

func TestLockBuildDir_DifferentDirsDoNotBlock(t *testing.T) {
	unlockA := lockBuildDir("/build/a-test")
	defer unlockA()
	done := make(chan struct{})
	go func() {
		unlockB := lockBuildDir("/build/b-test")
		unlockB()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a lock on one dir must not block another dir")
	}
}

func TestLockBuildDir_EmptyDirTakesNoLock(t *testing.T) {
	unlock1 := lockBuildDir("")
	unlock2 := lockBuildDir("") // would deadlock if "" were locked
	unlock1()
	unlock2()
}

func TestPipelineOverridesAllowed(t *testing.T) {
	t.Setenv(pipelineOverridesEnv, "1")
	assert.True(t, pipelineOverridesAllowed(TrustModeDev))
	assert.False(t, pipelineOverridesAllowed(TrustModeProd), "prod ignores the opt-in")
	assert.False(t, pipelineOverridesAllowed(""), "an unknown mode is not dev")

	for _, v := range []string{"", "0", "true", " 1"} {
		t.Setenv(pipelineOverridesEnv, v)
		assert.False(t, pipelineOverridesAllowed(TrustModeDev), "value %q", v)
	}
}
