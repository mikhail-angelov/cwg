package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func parseTransactionHash(value string) (common.Hash, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil || len(raw) != common.HashLength {
		return common.Hash{}, fmt.Errorf("invalid transaction hash: %s", value)
	}
	return common.BytesToHash(raw), nil
}

// Increase by 25%, rounding up, and always increase by at least one wei.
func cancellationGasPrice(price *big.Int) *big.Int {
	bumped := new(big.Int).Mul(price, big.NewInt(125))
	bumped.Add(bumped, big.NewInt(99))
	bumped.Div(bumped, big.NewInt(100))
	if bumped.Cmp(price) <= 0 {
		bumped.Add(price, big.NewInt(1))
	}
	return bumped
}

func (w *Wallet) CancelTransaction(ctx context.Context, txHash string) error {
	hash, err := parseTransactionHash(txHash)
	if err != nil {
		return err
	}
	original, pending, err := w.client.TransactionByHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("error finding transaction: %w", err)
	}
	if !pending {
		return fmt.Errorf("transaction is already mined and cannot be cancelled")
	}
	if original.Type() > types.DynamicFeeTxType {
		return fmt.Errorf("unsupported transaction type: %d", original.Type())
	}
	chainID := big.NewInt(1)
	if original.Protected() && original.ChainId().Cmp(chainID) != 0 {
		return fmt.Errorf("transaction is not on Ethereum mainnet")
	}
	signer := types.LatestSignerForChainID(chainID)
	from, err := types.Sender(signer, original)
	if err != nil {
		return fmt.Errorf("error determining sender: %w", err)
	}
	if !common.IsHexAddress(w.cfg.Wallet) || from != common.HexToAddress(w.cfg.Wallet) {
		return fmt.Errorf("transaction does not belong to the configured wallet")
	}
	suggested, err := w.client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("error getting gas price: %w", err)
	}
	feeCap := cancellationGasPrice(original.GasFeeCap())
	if feeCap.Cmp(suggested) < 0 {
		feeCap.Set(suggested)
	}
	var replacement *types.Transaction
	if original.Type() == types.DynamicFeeTxType {
		currentCap, tipCap, err := w.suggestedDynamicFees(ctx)
		if err != nil {
			return err
		}
		bumpedTip := cancellationGasPrice(original.GasTipCap())
		if tipCap.Cmp(bumpedTip) < 0 {
			currentCap.Add(currentCap, new(big.Int).Sub(bumpedTip, tipCap))
			tipCap.Set(bumpedTip)
		}
		if feeCap.Cmp(currentCap) < 0 {
			feeCap.Set(currentCap)
		}
		replacement = types.NewTx(&types.DynamicFeeTx{
			ChainID: chainID, Nonce: original.Nonce(), To: &from,
			Value: big.NewInt(0), Gas: 21000,
			GasFeeCap: feeCap, GasTipCap: tipCap,
		})
	} else {
		replacement = types.NewTransaction(original.Nonce(), from, big.NewInt(0), 21000, feeCap, nil)
	}
	fmt.Printf("Replacing: %s\nNonce: %d\n", hash.Hex(), original.Nonce())
	printGasCost(replacement.Gas(), replacement.GasFeeCap())
	keyBytes, err := decryptKey(w.cfg.WalletKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	defer zeroBytes(keyBytes)
	trimmed := strip0x(keyBytes)
	rawKey := make([]byte, hex.DecodedLen(len(trimmed)))
	defer zeroBytes(rawKey)
	if _, err := hex.Decode(rawKey, trimmed); err != nil {
		return fmt.Errorf("invalid private key hex: %w", err)
	}
	privateKey, err := crypto.ToECDSA(rawKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	if crypto.PubkeyToAddress(privateKey.PublicKey) != from {
		return fmt.Errorf("private key does not match the transaction sender")
	}
	signed, err := types.SignTx(replacement, signer, privateKey)
	if err != nil {
		return fmt.Errorf("error signing cancellation: %w", err)
	}
	// The original may have been mined while the user entered the password.
	_, pending, err = w.client.TransactionByHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("error rechecking transaction: %w", err)
	}
	if !pending {
		return fmt.Errorf("transaction was mined before cancellation could be sent")
	}
	if err := w.client.SendTransaction(ctx, signed); err != nil {
		return fmt.Errorf("error sending cancellation: %w", err)
	}
	fmt.Printf("Cancellation sent! Tx Hash: %s\nCancellation takes effect when this replacement is mined.\n", signed.Hash().Hex())
	return nil
}
