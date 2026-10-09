package aauth

import (
	"net/http"
	"os"
	"testing"
)

// TestMain lets discovery reach the package's local test servers (plain
// http on loopback), which the guarded default refuses. discovery_test.go
// tests the guarded client directly.
func TestMain(m *testing.M) {
	defaultDiscoveryClient = http.DefaultClient
	defaultEgressClient = http.DefaultClient
	os.Exit(m.Run())
}
