package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	InfuraAPIKey    string `json:"infura_api_key"`
	EtherscanAPIKey string `json:"etherscan_api_key"`
	USDTContract    string `json:"usd_contract"`
	Wallet          string `json:"wallet"`
	WalletKey       string `json:"wallet_key"`
}

func LoadConfig(path string) (*Config, error) {
	var cfg Config

	// 1. Try to load from JSON file
	// Sanitize path to prevent path traversal (gosec G304)
	if !isSafePath(path) {
		return nil, fmt.Errorf("invalid config file path")
	}
	// nolint:gosec // Path is sanitized by isSafePath
	f, err := os.Open(path)
	if err == nil {
		defer func() {
			if closeErr := f.Close(); closeErr != nil {
				// Log the error but don't fail the config load
				fmt.Fprintf(os.Stderr, "warning: failed to close config file: %v\n", closeErr)
			}
		}()
		decoder := json.NewDecoder(f)
		if decodeErr := decoder.Decode(&cfg); decodeErr != nil {
			return nil, fmt.Errorf("failed to decode config file: %w", decodeErr)
		}
	} else if !os.IsNotExist(err) {
		// If error is something other than "file not found", return it
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}

	// 2. Override with Environment Variables
	if val := os.Getenv("CWG_INFURA_API_KEY"); val != "" {
		cfg.InfuraAPIKey = val
	}
	if val := os.Getenv("CWG_ETHERSCAN_API_KEY"); val != "" {
		cfg.EtherscanAPIKey = val
	}
	if val := os.Getenv("CWG_USDT_CONTRACT"); val != "" {
		cfg.USDTContract = val
	}
	if val := os.Getenv("CWG_WALLET"); val != "" {
		cfg.Wallet = val
	}
	if val := os.Getenv("CWG_WALLET_KEY"); val != "" {
		cfg.WalletKey = val
	}

	return &cfg, nil
}

// isSafePath checks if the path is safe to open (no directory traversal)
func isSafePath(path string) bool {
	// Clean the path and check if it contains any ".." components
	cleanPath := filepath.Clean(path)
	// Check if the cleaned path starts with ".." or contains "/.." or "\.."
	if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/..") || strings.Contains(cleanPath, "\\..") {
		return false
	}
	// Also check for absolute paths or paths starting with current directory are fine
	return true
}
