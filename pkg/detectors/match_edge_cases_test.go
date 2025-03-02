package detectors

import (
	"net/http/httptest"
	"testing"
)

func TestDetectorMatch_DisabledDetectors(t *testing.T) {
	// Create a request with potential attack payloads
	req := httptest.NewRequest("GET", "http://example.com/search?q=1%27+OR+%271%27%3D%271", nil)
	req.Header.Set("User-Agent", "nmap scanner")
	req.Header.Set("Referer", "http://example.com/page?id=../../etc/passwd")

	// Test SQLi detector when disabled
	t.Run("Disabled SQLi Detector", func(t *testing.T) {
		detector := NewSQLiDetector()
		detector.Disable()

		detected, _ := detector.Match(req)
		if detected {
			t.Error("Disabled SQLi detector should not detect attacks")
		}
	})

	// Test XSS detector when disabled
	t.Run("Disabled XSS Detector", func(t *testing.T) {
		detector := NewXSSDetector()
		detector.Disable()

		detected, _ := detector.Match(req)
		if detected {
			t.Error("Disabled XSS detector should not detect attacks")
		}
	})

	// Test Path Traversal detector when disabled
	t.Run("Disabled Path Traversal Detector", func(t *testing.T) {
		detector := NewPathTraversalDetector()
		detector.Disable()

		detected, _ := detector.Match(req)
		if detected {
			t.Error("Disabled Path Traversal detector should not detect attacks")
		}
	})

	// Test Command Injection detector when disabled
	t.Run("Disabled Command Injection Detector", func(t *testing.T) {
		detector := NewCommandInjectionDetector()
		detector.Disable()

		detected, _ := detector.Match(req)
		if detected {
			t.Error("Disabled Command Injection detector should not detect attacks")
		}
	})

	// Test User Agent detector when disabled
	t.Run("Disabled User Agent Detector", func(t *testing.T) {
		detector := NewUserAgentDetector()
		detector.Disable()

		detected, _ := detector.Match(req)
		if detected {
			t.Error("Disabled User Agent detector should not detect attacks")
		}
	})
}

// TestMatchEmptyRequest tests the behavior of detectors when given an empty request
func TestMatchEmptyRequest(t *testing.T) {
	// Create an empty request
	req := httptest.NewRequest("GET", "http://example.com/", nil)

	// Test all detectors with empty request
	t.Run("SQLi Detector with empty request", func(t *testing.T) {
		detector := NewSQLiDetector()
		detected, _ := detector.Match(req)
		if detected {
			t.Error("SQLi detector should not detect attacks in empty request")
		}
	})

	t.Run("XSS Detector with empty request", func(t *testing.T) {
		detector := NewXSSDetector()
		detected, _ := detector.Match(req)
		if detected {
			t.Error("XSS detector should not detect attacks in empty request")
		}
	})

	t.Run("Path Traversal Detector with empty request", func(t *testing.T) {
		detector := NewPathTraversalDetector()
		detected, _ := detector.Match(req)
		if detected {
			t.Error("Path Traversal detector should not detect attacks in empty request")
		}
	})

	t.Run("Command Injection Detector with empty request", func(t *testing.T) {
		detector := NewCommandInjectionDetector()
		detected, _ := detector.Match(req)
		if detected {
			t.Error("Command Injection detector should not detect attacks in empty request")
		}
	})

	t.Run("User Agent Detector with empty request", func(t *testing.T) {
		detector := NewUserAgentDetector()
		detected, _ := detector.Match(req)
		if detected {
			t.Error("User Agent detector should not detect attacks in empty request")
		}
	})
}
