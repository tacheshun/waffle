package detectors

import "testing"

func TestDetectorEnableDisable(t *testing.T) {
	// Test SQL Injection detector
	t.Run("SQLi Detector", func(t *testing.T) {
		detector := NewSQLiDetector()

		// Check initial state
		if !detector.IsEnabled() {
			t.Error("SQLi detector should be enabled by default")
		}

		// Test disable
		detector.Disable()
		if detector.IsEnabled() {
			t.Error("SQLi detector should be disabled after Disable() call")
		}

		// Test enable
		detector.Enable()
		if !detector.IsEnabled() {
			t.Error("SQLi detector should be enabled after Enable() call")
		}
	})

	// Test XSS detector
	t.Run("XSS Detector", func(t *testing.T) {
		detector := NewXSSDetector()

		// Check initial state
		if !detector.IsEnabled() {
			t.Error("XSS detector should be enabled by default")
		}

		// Test disable
		detector.Disable()
		if detector.IsEnabled() {
			t.Error("XSS detector should be disabled after Disable() call")
		}

		// Test enable
		detector.Enable()
		if !detector.IsEnabled() {
			t.Error("XSS detector should be enabled after Enable() call")
		}
	})

	// Test Path Traversal detector
	t.Run("Path Traversal Detector", func(t *testing.T) {
		detector := NewPathTraversalDetector()

		// Check initial state
		if !detector.IsEnabled() {
			t.Error("Path Traversal detector should be enabled by default")
		}

		// Test disable
		detector.Disable()
		if detector.IsEnabled() {
			t.Error("Path Traversal detector should be disabled after Disable() call")
		}

		// Test enable
		detector.Enable()
		if !detector.IsEnabled() {
			t.Error("Path Traversal detector should be enabled after Enable() call")
		}
	})

	// Test Command Injection detector
	t.Run("Command Injection Detector", func(t *testing.T) {
		detector := NewCommandInjectionDetector()

		// Check initial state
		if !detector.IsEnabled() {
			t.Error("Command Injection detector should be enabled by default")
		}

		// Test disable
		detector.Disable()
		if detector.IsEnabled() {
			t.Error("Command Injection detector should be disabled after Disable() call")
		}

		// Test enable
		detector.Enable()
		if !detector.IsEnabled() {
			t.Error("Command Injection detector should be enabled after Enable() call")
		}
	})

	// Test User Agent detector
	t.Run("User Agent Detector", func(t *testing.T) {
		detector := NewUserAgentDetector()

		// Check initial state
		if !detector.IsEnabled() {
			t.Error("User Agent detector should be enabled by default")
		}

		// Test disable
		detector.Disable()
		if detector.IsEnabled() {
			t.Error("User Agent detector should be disabled after Disable() call")
		}

		// Test enable
		detector.Enable()
		if !detector.IsEnabled() {
			t.Error("User Agent detector should be enabled after Enable() call")
		}
	})
}
