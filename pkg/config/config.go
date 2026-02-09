package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds the server configuration
type Config struct {
	// Server settings
	ListenAddr string
	Port       int

	// TSIG settings
	TSIGKey       string
	TSIGSecret    string
	TSIGAlgorithm string

	// Kubernetes settings
	Namespace string

	// Zone settings
	AllowedZones []string

	// Custom labels for DNSEndpoint resources
	CustomLabels map[string]string

	// Logging
	LogLevel string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	cfg := &Config{
		ListenAddr:    getEnv("LISTEN_ADDR", "0.0.0.0"),
		Port:          getEnvInt("PORT", 5353),
		TSIGKey:       getEnv("TSIG_KEY", "opnsense-ddns"),
		TSIGSecret:    getEnv("TSIG_SECRET", "changeme"),
		TSIGAlgorithm: getEnv("TSIG_ALGORITHM", "hmac-sha256"),
		Namespace:     getEnv("NAMESPACE", "default"),
		AllowedZones:  getEnvSlice("ALLOWED_ZONES", ","),
		CustomLabels:  getEnvMap("CUSTOM_LABELS", ",", "="),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.TSIGKey == "" {
		return fmt.Errorf("TSIG_KEY is required")
	}
	if c.TSIGSecret == "" {
		return fmt.Errorf("TSIG_SECRET is required")
	}
	if len(c.AllowedZones) == 0 {
		return fmt.Errorf("at least one zone must be configured in ALLOWED_ZONES")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("PORT must be between 1 and 65535")
	}
	return nil
}

// IsZoneAllowed checks if a zone is in the allowed zones list
func (c *Config) IsZoneAllowed(zone string) bool {
	// Normalize zone by ensuring it ends with a dot
	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	for _, allowedZone := range c.AllowedZones {
		if !strings.HasSuffix(allowedZone, ".") {
			allowedZone = allowedZone + "."
		}
		if zone == allowedZone || strings.HasSuffix(zone, "."+allowedZone) {
			return true
		}
	}
	return false
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvSlice(key, separator string) []string {
	value := os.Getenv(key)
	if value == "" {
		return []string{}
	}
	parts := strings.Split(value, separator)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func getEnvMap(key, pairSeparator, kvSeparator string) map[string]string {
	value := os.Getenv(key)
	if value == "" {
		return map[string]string{}
	}
	result := make(map[string]string)
	pairs := strings.Split(value, pairSeparator)
	for _, pair := range pairs {
		if trimmed := strings.TrimSpace(pair); trimmed != "" {
			parts := strings.SplitN(trimmed, kvSeparator, 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v := strings.TrimSpace(parts[1])
				if k != "" {
					result[k] = v
				}
			}
		}
	}
	return result
}
