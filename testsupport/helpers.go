package testsupport

import (
	"egressz/sidecar"
)

// BumpResolution invalidates outstanding resolution answers (late-drop token).
func (t *Topology) BumpResolution() {
	// The sidecar owns the table; expose the bump through a small wrapper so
	// scenarios can force the late-resolution generation forward.
	t.Sidecar.BumpResolution()
}

// ResolutionToken returns the current late-resolution generation token.
func (t *Topology) ResolutionToken() int64 { return t.Sidecar.ResolutionToken() }

// Ensure sidecar exposes the two helpers used above.
var _ = sidecar.ErrLateResolution
