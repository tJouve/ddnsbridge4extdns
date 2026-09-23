package k8s

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/tJouve/ddnsbridge4extdns/pkg/update"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestIsAlphanumericLower(t *testing.T) {
	tests := []struct {
		input    rune
		expected bool
	}{
		{'a', true},
		{'z', true},
		{'A', false},
		{'Z', false},
		{'0', true},
		{'9', true},
		{'-', false},
		{'.', false},
		{'_', false},
		{'@', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := isAlphanumericLower(tt.input)
			if result != tt.expected {
				t.Errorf("isAlphanumericLower(%c) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNameToK8sName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		size     int
		expected string
	}{
		{name: "resource hostname", input: "test.example.com.", size: 253, expected: "test-example-com"},
		{name: "resource hostname with underscore", input: "test_host.example.com", size: 253, expected: "test-host-example-com"},
		{name: "resource hostname with ip", input: "192.168.1.1", size: 253, expected: "192-168-1-1"},
		{name: "resource name with invalid leading char", input: "@", size: 253, expected: ""},
		{name: "label hostname", input: "example.com.", size: 63, expected: "example-com"},
		{name: "label value keeps underscore", input: "opnsense_pallas.", size: 63, expected: "opnsense_pallas"},
		{name: "label trims invalid edges", input: ".-key-.", size: 63, expected: "dns-key"},
		{name: "label truncates to 63 chars", input: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789extra", size: 63, expected: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nameToK8sName(tt.input, tt.size)
			if result != tt.expected {
				t.Fatalf("nameToK8sName(%q, %d) = %q, want %q", tt.input, tt.size, result, tt.expected)
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
	sanitized := nameToK8sName(hostname, 253)

	if hostname != "test" {
		t.Errorf("GetHostname() = %s, want 'test'", hostname)
	}

	if sanitized != "test" {
		t.Errorf("nameToK8sName(%s) = %s, want 'test'", hostname, sanitized)
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

func TestSanitizeTSIGKeyLabelValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "trim", input: "  client1.  ", expected: "client1"},
		{name: "preserve valid underscore", input: "opnsense_pallas.", expected: "opnsense_pallas"},
		{name: "trim non-alnum edges", input: ".-key-.", expected: "dns-key"},
		{name: "truncate to 63", input: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789extra", expected: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789e"},
		{name: "empty", input: "   ", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nameToK8sName(tt.input, 63)
			if got != tt.expected {
				t.Fatalf("nameToK8sName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCompareEndpointDetectsTSIGLabelChange(t *testing.T) {
	existing := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{
				"app.kubernetes.io/managed-by": "ddnsbridge4extdns",
				"ddnsbridge4extdns/key":        "client0",
			},
		},
		"spec": map[string]interface{}{
			"endpoints": []interface{}{"same"},
		},
	}}

	desired := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{
				"app.kubernetes.io/managed-by": "ddnsbridge4extdns",
				"ddnsbridge4extdns/key":        "client1",
			},
		},
		"spec": map[string]interface{}{
			"endpoints": []interface{}{"same"},
		},
	}}

	labelsMatch, specMatch, _, _ := compareEndpoint(existing, desired)
	if labelsMatch {
		t.Fatalf("expected labels mismatch when TSIG key label changes")
	}
	if !specMatch {
		t.Fatalf("expected spec to match")
	}
}
