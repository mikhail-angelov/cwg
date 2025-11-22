package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	INFURA_API_KEY    string `json:"infura_api_key"`
	ETHERSCAN_API_KEY string `json:"etherscan_api_key"`
	USDT_CONTRACT     string `json:"usd_contract"`
	WALLET            string `json:"wallet"`
	WALLET_KEY        string `json:"wallet_key"`
}

func LoadConfig(path string) (*Config, error) {
	var cfg Config

	// 1. Try to load from JSON file
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		decoder := json.NewDecoder(f)
		if err := decoder.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("failed to decode config file: %w", err)
		}
	} else if !os.IsNotExist(err) {
		// If error is something other than "file not found", return it
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}

	// 2. Override with Environment Variables
	if val := os.Getenv("CWG_INFURA_API_KEY"); val != "" {
		cfg.INFURA_API_KEY = val
	}
	if val := os.Getenv("CWG_ETHERSCAN_API_KEY"); val != "" {
		cfg.ETHERSCAN_API_KEY = val
	}
	if val := os.Getenv("CWG_USDT_CONTRACT"); val != "" {
		cfg.USDT_CONTRACT = val
	}
	if val := os.Getenv("CWG_WALLET"); val != "" {
		cfg.WALLET = val
	}
	if val := os.Getenv("CWG_WALLET_KEY"); val != "" {
		cfg.WALLET_KEY = val
	}

	return &cfg, nil
}
