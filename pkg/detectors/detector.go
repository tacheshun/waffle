// Package detectors contains various detection mechanisms for the Waffle WAF.
package detectors

import (
	"net/http"

	"github.com/tacheshun/waffle/pkg/types"
)

// Detector defines the interface that all detection rules must implement.
// Each detector is responsible for identifying a specific type of attack
// within an HTTP request.
type Detector interface {
	// Match examines the given HTTP request and determines if it matches
	// the criteria for a potential attack.
	// It returns true if a match is found, along with a BlockReason detailing
	// the specific rule and reason for the block.
	// It returns false if no match is found, along with a nil BlockReason.
	Match(*http.Request) (bool, *types.BlockReason)

	// IsEnabled checks if the detector is currently active.
	IsEnabled() bool

	// Enable activates the detector.
	Enable()

	// Disable deactivates the detector.
	Disable()

	// Name returns the unique identifier for the detector.
	Name() string
}
