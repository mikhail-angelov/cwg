package main

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestCheckBalance(t *testing.T) {
	// Setup mock client
	mockClient := &MockClient{
		BalanceAtFunc: func(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
			return big.NewInt(1000000000000000000), nil // 1 ETH
		},
		CallContractFunc: func(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
			// Check method signature
			if len(msg.Data) >= 4 {
				sig := common.Bytes2Hex(msg.Data[:4])
				if sig == "313ce567" { // decimals
					return common.LeftPadBytes(big.NewInt(6).Bytes(), 32), nil
				}
				if sig == "70a08231" { // balanceOf
					return common.LeftPadBytes(big.NewInt(1000000).Bytes(), 32), nil
				}
			}
			return common.LeftPadBytes(big.NewInt(0).Bytes(), 32), nil
		},
	}

	cfg := &Config{
		Wallet:       "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
		InfuraAPIKey: "test",
		USDTContract: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
	}

	w := NewWallet(cfg, mockClient)

	// We need to capture stdout to verify output, but for now let's just ensure no error
	// and we can rely on the fact that it calls the mock.
	err := w.CheckBalance(context.Background(), "0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
	if err != nil {
		t.Errorf("CheckBalance failed: %v", err)
	}
}

func TestLastTransactions(t *testing.T) {
	mockClient := &MockClient{
		BlockNumberFunc: func(ctx context.Context) (uint64, error) {
			return 10000, nil
		},
		FilterLogsFunc: func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
			return []types.Log{
				{
					TxHash:      common.HexToHash("0x1"),
					BlockNumber: 9999,
					Topics: []common.Hash{
						common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"), // Transfer
						common.HexToHash("0x000000000000000000000000742d35Cc6634C0532925a3b844Bc454e4438f44e"), // From
						common.HexToHash("0x0000000000000000000000001234567890123456789012345678901234567890"), // To
					},
					Data: common.LeftPadBytes(big.NewInt(5000000).Bytes(), 32), // 5 USDT
				},
			}, nil
		},
		CallContractFunc: func(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
			// Decimals call
			return common.LeftPadBytes(big.NewInt(6).Bytes(), 32), nil
		},
	}

	cfg := &Config{
		Wallet:       "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
		InfuraAPIKey: "test",
		USDTContract: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
	}

	w := NewWallet(cfg, mockClient)

	err := w.LastTransactions(context.Background(), "0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
	if err != nil {
		t.Errorf("LastTransactions failed: %v", err)
	}
}
