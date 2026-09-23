package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v2"
)

const defaultTSIGAlgorithm = "hmac-sha256"

var supportedTSIGAlgorithms = map[string]struct{}{
	"hmac-sha1":   {},
	"hmac-sha256": {},
	"hmac-sha512": {},
}

// TSIGEntry represents one TSIG key configuration
type TSIGEntry struct {
	Key       string `yaml:"key"`
	Secret    string `yaml:"secret"`
	Algorithm string `yaml:"algorithm"`
}

type tsigFileConfig struct {
	TSIGs []TSIGEntry `yaml:"TSIGs"`
}

// Config holds the server configuration
type Config struct {
	// Server settings
	ListenAddr string
	Port       int

	// TSIG settings
	TSIGFile string
	TSIGs    []TSIGEntry

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
		ListenAddr:   getEnv("LISTEN_ADDR", "0.0.0.0"),
		Port:         getEnvInt("PORT", 5353),
		Namespace:    getEnv("NAMESPACE", "default"),
		AllowedZones: getEnvSlice("ALLOWED_ZONES", ","),
		CustomLabels: getEnvMap("CUSTOM_LABELS", ",", "="),
		LogLevel:     getEnv("LOG_LEVEL", "info"),
		TSIGFile:     strings.TrimSpace(getEnv("TSIG_FILE", "")),
	}

	if cfg.TSIGFile == "" {
		return nil, fmt.Errorf("invalid configuration: TSIG_FILE is required")
	}

	tsigs, err := loadTSIGsFromFile(cfg.TSIGFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TSIG_FILE %q: %w", cfg.TSIGFile, err)
	}
	cfg.TSIGs = tsigs

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if len(c.TSIGs) == 0 {
		if c.TSIGFile != "" {
			return fmt.Errorf("TSIG_FILE must contain at least one TSIG entry")
		}
		return fmt.Errorf("at least one TSIG entry is required")
	}

	for i := range c.TSIGs {
		entry := &c.TSIGs[i]
		entry.Key = strings.TrimSpace(entry.Key)
		entry.Secret = strings.TrimSpace(entry.Secret)
		entry.Algorithm = strings.TrimSpace(strings.ToLower(entry.Algorithm))

		if entry.Algorithm == "" {
			entry.Algorithm = defaultTSIGAlgorithm
		}

		if entry.Key == "" {
			return fmt.Errorf("TSIG entry #%d key is required", i+1)
		}
		if entry.Secret == "" {
			return fmt.Errorf("TSIG entry #%d secret is required", i+1)
		}
		if _, err := base64.StdEncoding.DecodeString(entry.Secret); err != nil {
			return fmt.Errorf("TSIG entry #%d secret must be valid base64: %w", i+1, err)
		}
		if _, ok := supportedTSIGAlgorithms[entry.Algorithm]; !ok {
			return fmt.Errorf("TSIG entry #%d has unsupported algorithm %q", i+1, entry.Algorithm)
		}
	}

	seenKeys := make(map[string]int, len(c.TSIGs))
	for i, entry := range c.TSIGs {
		normalized := normalizeTSIGKeyName(entry.Key)
		if prevIdx, exists := seenKeys[normalized]; exists {
			return fmt.Errorf("TSIG entry #%d duplicates entry #%d for key %q", i+1, prevIdx+1, entry.Key)
		}
		seenKeys[normalized] = i
	}

	if len(c.AllowedZones) == 0 {
		return fmt.Errorf("at least one zone must be configured in ALLOWED_ZONES")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("PORT must be between 1 and 65535")
	}
	return nil
}

// LookupTSIG finds TSIG configuration by key name (with/without trailing dot).
func (c *Config) LookupTSIG(keyName string) (TSIGEntry, bool) {
	normalized := normalizeTSIGKeyName(keyName)
	if normalized == "" {
		return TSIGEntry{}, false
	}

	for _, entry := range c.TSIGs {
		if normalizeTSIGKeyName(entry.Key) == normalized {
			return entry, true
		}
	}

	return TSIGEntry{}, false
}

// TSIGSecretMap returns secrets for all configured TSIG keys, with and without trailing dots.
func (c *Config) TSIGSecretMap() map[string]string {
	ts := make(map[string]string, len(c.TSIGs)*2)
	for _, entry := range c.TSIGs {
		key := strings.TrimSpace(entry.Key)
		if key == "" {
			continue
		}

		addTSIGKeyVariants(ts, key, entry.Secret)
	}
	return ts
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

func loadTSIGsFromFile(filePath string) ([]TSIGEntry, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(string(content)) == "" {
		return nil, fmt.Errorf("file is empty")
	}

	var fileCfg tsigFileConfig
	if err := yaml.Unmarshal(content, &fileCfg); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	if len(fileCfg.TSIGs) == 0 {
		return nil, fmt.Errorf("TSIGs must contain at least one entry")
	}

	return fileCfg.TSIGs, nil
}

func normalizeTSIGKeyName(keyName string) string {
	normalized := strings.TrimSpace(strings.ToLower(keyName))
	if normalized == "" {
		return ""
	}
	return strings.TrimSuffix(normalized, ".")
}

func addTSIGKeyVariants(m map[string]string, key, secret string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}

	m[key] = secret
	if strings.HasSuffix(key, ".") {
		m[strings.TrimSuffix(key, ".")] = secret
	} else {
		m[key+"."] = secret
	}

	canonical := strings.ToLower(key)
	m[canonical] = secret
	if strings.HasSuffix(canonical, ".") {
		m[strings.TrimSuffix(canonical, ".")] = secret
	} else {
		m[canonical+"."] = secret
	}
}
