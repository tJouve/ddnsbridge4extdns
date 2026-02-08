package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Set up environment variables
	os.Setenv("TSIG_KEY", "test-key")
	os.Setenv("TSIG_SECRET", "test-secret")
	os.Setenv("ALLOWED_ZONES", "example.com,example.org")
	defer os.Clearenv()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	if cfg.TSIGKey != "test-key" {
		t.Errorf("Expected TSIGKey 'test-key', got '%s'", cfg.TSIGKey)
	}

	if cfg.TSIGSecret != "test-secret" {
		t.Errorf("Expected TSIGSecret 'test-secret', got '%s'", cfg.TSIGSecret)
	}

	if len(cfg.AllowedZones) != 2 {
		t.Errorf("Expected 2 allowed zones, got %d", len(cfg.AllowedZones))
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		shouldErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				TSIGKey:      "test-key",
				TSIGSecret:   "test-secret",
				AllowedZones: []string{"example.com"},
				Port:         53,
			},
			shouldErr: false,
		},
		{
			name: "missing TSIG key",
			config: &Config{
				TSIGSecret:   "test-secret",
				AllowedZones: []string{"example.com"},
				Port:         53,
			},
			shouldErr: true,
		},
		{
			name: "missing TSIG secret",
			config: &Config{
				TSIGKey:      "test-key",
				AllowedZones: []string{"example.com"},
				Port:         53,
			},
			shouldErr: true,
		},
		{
			name: "no allowed zones",
			config: &Config{
				TSIGKey:      "test-key",
				TSIGSecret:   "test-secret",
				AllowedZones: []string{},
				Port:         53,
			},
			shouldErr: true,
		},
		{
			name: "invalid port",
			config: &Config{
				TSIGKey:      "test-key",
				TSIGSecret:   "test-secret",
				AllowedZones: []string{"example.com"},
				Port:         0,
			},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.shouldErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestIsZoneAllowed(t *testing.T) {
	cfg := &Config{
		AllowedZones: []string{"example.com", "test.org"},
	}

	tests := []struct {
		zone    string
		allowed bool
	}{
		{"example.com", true},
		{"example.com.", true},
		{"test.example.com", true},
		{"test.example.com.", true},
		{"test.org", true},
		{"test.org.", true},
		{"sub.test.org", true},
		{"notallowed.com", false},
		{"notallowed.com.", false},
		{"example.net", false},
	}

	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			result := cfg.IsZoneAllowed(tt.zone)
			if result != tt.allowed {
				t.Errorf("IsZoneAllowed(%s) = %v, want %v", tt.zone, result, tt.allowed)
			}
		})
	}
}
