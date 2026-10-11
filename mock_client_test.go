package main

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type MockClient struct {
	BalanceAtFunc          func(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error)
	CallContractFunc       func(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	BlockNumberFunc        func(ctx context.Context) (uint64, error)
	FilterLogsFunc         func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
	TransactionByHashFunc  func(ctx context.Context, txHash common.Hash) (*types.Transaction, bool, error)
	TransactionReceiptFunc func(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	PendingNonceAtFunc     func(ctx context.Context, account common.Address) (uint64, error)
	HeaderByNumberFunc     func(ctx context.Context, number *big.Int) (*types.Header, error)
	SuggestGasTipCapFunc   func(ctx context.Context) (*big.Int, error)
	SuggestGasPriceFunc    func(ctx context.Context) (*big.Int, error)
	EstimateGasFunc        func(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	SendTransactionFunc    func(ctx context.Context, tx *types.Transaction) error
	CloseFunc              func()
}

func (m *MockClient) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	if m.BalanceAtFunc != nil {
		return m.BalanceAtFunc(ctx, account, blockNumber)
	}
	return big.NewInt(0), nil
}

func (m *MockClient) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if m.CallContractFunc != nil {
		return m.CallContractFunc(ctx, msg, blockNumber)
	}
	return nil, nil
}

func (m *MockClient) BlockNumber(ctx context.Context) (uint64, error) {
	if m.BlockNumberFunc != nil {
		return m.BlockNumberFunc(ctx)
	}
	return 0, nil
}

func (m *MockClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	if m.FilterLogsFunc != nil {
		return m.FilterLogsFunc(ctx, q)
	}
	return nil, nil
}

func (m *MockClient) TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error) {
	if m.TransactionByHashFunc != nil {
		return m.TransactionByHashFunc(ctx, hash)
	}
	return nil, false, ethereum.NotFound
}

func (m *MockClient) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	if m.TransactionReceiptFunc != nil {
		return m.TransactionReceiptFunc(ctx, txHash)
	}
	return nil, nil
}

func (m *MockClient) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	if m.PendingNonceAtFunc != nil {
		return m.PendingNonceAtFunc(ctx, account)
	}
	return 0, nil
}

func (m *MockClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	if m.HeaderByNumberFunc != nil {
		return m.HeaderByNumberFunc(ctx, number)
	}
	return &types.Header{BaseFee: big.NewInt(1_000_000_000)}, nil
}

func (m *MockClient) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	if m.SuggestGasTipCapFunc != nil {
		return m.SuggestGasTipCapFunc(ctx)
	}
	return big.NewInt(10_000_000), nil
}

func (m *MockClient) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	if m.SuggestGasPriceFunc != nil {
		return m.SuggestGasPriceFunc(ctx)
	}
	return big.NewInt(0), nil
}

func (m *MockClient) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	if m.EstimateGasFunc != nil {
		return m.EstimateGasFunc(ctx, msg)
	}
	return 0, nil
}

func (m *MockClient) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	if m.SendTransactionFunc != nil {
		return m.SendTransactionFunc(ctx, tx)
	}
	return nil
}

func (m *MockClient) Close() {
	if m.CloseFunc != nil {
		m.CloseFunc()
	}
}
