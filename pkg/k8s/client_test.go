package k8s

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/tJouve/ddnstoextdns/pkg/update"
)

func TestSanitizeResourceName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test.example.com.", "test-example-com"},
		{"test.example.com", "test-example-com"},
		{"subdomain.test.example.com", "subdomain-test-example-com"},
		{"test_host.example.com", "test-host-example-com"},
		{"123.example.com", "123-example-com"}, // starts with number - but we allow it
		{"@", ""},                               // empty after sanitization
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeResourceName(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeResourceName(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		input       string
		expectedLen int
	}{
		{"example.com.", 11},
		{"example.com", 11},
		{"test.org", 8},
		{"very-long-domain-name-that-exceeds-the-kubernetes-label-limit.com", 63}, // truncated to 63
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeLabel(tt.input)
			if len(result) != tt.expectedLen {
				t.Errorf("sanitizeLabel(%s) length = %d, want %d (result: %s)", tt.input, len(result), tt.expectedLen, result)
			}
			// Check length constraint
			if len(result) > 63 {
				t.Errorf("sanitizeLabel(%s) returned string longer than 63 characters: %d", tt.input, len(result))
			}
		})
	}
}

func TestIsAlphanumeric(t *testing.T) {
	tests := []struct {
		input    rune
		expected bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'-', false},
		{'.', false},
		{'_', false},
		{'@', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := isAlphanumeric(tt.input)
			if result != tt.expected {
				t.Errorf("isAlphanumeric(%c) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDNSNameToK8sName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test.example.com", "test-example-com"},
		{"test_host", "test-host"},
		{"test-host", "test-host"},
		{"test.host_name", "test-host-name"},
		{"192.168.1.1", "192-168-1-1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := dnsNameToK8sName(tt.input)
			if result != tt.expected {
				t.Errorf("dnsNameToK8sName(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestUpdateGetHostname(t *testing.T) {
	// This tests the integration between update.DNSUpdate.GetHostname() and k8s sanitization
	upd := &update.DNSUpdate{
		Name: "test.example.com.",
		Zone: "example.com.",
	}

	hostname := upd.GetHostname()
	sanitized := sanitizeResourceName(hostname)

	if hostname != "test" {
		t.Errorf("GetHostname() = %s, want 'test'", hostname)
	}

	if sanitized != "test" {
		t.Errorf("sanitizeResourceName(%s) = %s, want 'test'", hostname, sanitized)
	}
}

func TestUpdateTypeHandling(t *testing.T) {
	// Test that we handle all update types
	tests := []struct {
		updateType update.UpdateType
		name       string
	}{
		{update.UpdateTypeCreate, "create"},
		{update.UpdateTypeUpdate, "update"},
		{update.UpdateTypeDelete, "delete"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upd := &update.DNSUpdate{
				Type:       tt.updateType,
				RecordType: dns.TypeA,
				Name:       "test.example.com.",
				Zone:       "example.com.",
			}

			// Just verify the type is set correctly
			if upd.Type != tt.updateType {
				t.Errorf("Update type = %v, want %v", upd.Type, tt.updateType)
			}
		})
	}
}
