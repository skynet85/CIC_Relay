package main

import "sync"

// buildDirLocks holds one mutex per build directory. A pipeline or repo CI run deletes its
// build directory, clones into it and builds from it across several workflow steps; two runs on
// the same directory at once would delete each other's checkout, and an artifact could be built
// from one request's source while its provenance names another's. Runs on one directory are
// therefore serialized for the whole workflow.
var buildDirLocks sync.Map // build dir → *sync.Mutex

// lockBuildDir locks dir for one workflow run and returns the unlock function. An empty dir
// (no build directory configured or requested) takes no lock: such a run fails at its first step.
func lockBuildDir(dir string) func() {
	if dir == "" {
		return func() {}
	}
	mu, _ := buildDirLocks.LoadOrStore(dir, &sync.Mutex{})
	m := mu.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}
