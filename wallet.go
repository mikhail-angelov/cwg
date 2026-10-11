package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"

	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const usdtABIPath = "./usdt-abi.json"

type Wallet struct {
	cfg    *Config
	client Client
}

func NewWallet(cfg *Config, client Client) *Wallet {
	return &Wallet{cfg: cfg, client: client}
}

func getClient(key string) (Client, error) {
	providerURL := "https://mainnet.infura.io/v3/" + key
	client, err := ethclient.Dial(providerURL)
	if err != nil {
		return nil, fmt.Errorf("error connecting to Ethereum: %w", err)
	}
	return client, nil
}

func getUSDTABI() (abi.ABI, error) {
	abiBytes, err := os.ReadFile(usdtABIPath)
	if err != nil {
		return abi.ABI{}, fmt.Errorf("error reading ABI: %w", err)
	}
	usdtABI, err := abi.JSON(strings.NewReader(string(abiBytes)))
	if err != nil {
		return abi.ABI{}, fmt.Errorf("error parsing ABI: %w", err)
	}
	return usdtABI, nil
}

func (w *Wallet) CreateWallet() error {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("error generating key: %w", err)
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Printf("New Wallet:\nAddress: %s\nPrivate Key: %x\n", address.Hex(), crypto.FromECDSA(privateKey))
	return nil
}
func (w *Wallet) CheckBalance(ctx context.Context, address string) error {
	if address == "" {
		address = w.cfg.Wallet
	}
	fmt.Println("Balance for: ", address)
	client := w.client

	if !common.IsHexAddress(address) {
		return fmt.Errorf("invalid Ethereum address: %s", address)
	}
	addr := common.HexToAddress(address)

	// ETH Balance
	ethBalance, err := client.BalanceAt(ctx, addr, nil)
	if err != nil {
		return fmt.Errorf("error getting ETH balance: %w", err)
	}
	fmt.Printf("ETH Balance: %s (%s)\n", weiToEther(ethBalance), address)

	// USDT Balance
	usdtABI, err := getUSDTABI()
	if err != nil {
		return err
	}
	usdtAddress := w.cfg.USDTContract
	contractAddr := common.HexToAddress(usdtAddress)
	data, err := usdtABI.Pack("balanceOf", addr)
	if err != nil {
		return fmt.Errorf("error packing balanceOf: %w", err)
	}
	callMsg := ethereum.CallMsg{To: &contractAddr, Data: data}
	res, err := client.CallContract(ctx, callMsg, nil)
	if err != nil {
		return fmt.Errorf("error calling contract: %w", err)
	}
	balance := new(big.Int).SetBytes(res)
	decimals := getUSDTDecimals(ctx, client, usdtABI, contractAddr)
	fmt.Printf("USDT Balance: %s (%s)\n", formatTokenAmount(balance, decimals), address)
	return nil
}

func weiToEther(wei *big.Int) string {
	f := new(big.Float).SetInt(wei)
	ethValue := new(big.Float).Quo(f, big.NewFloat(1e18))
	return ethValue.Text('f', 6)
}

func (w *Wallet) suggestedDynamicFees(ctx context.Context) (feeCap, tip *big.Int, err error) {
	header, err := w.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting latest block: %w", err)
	}
	if header == nil || header.BaseFee == nil {
		return nil, nil, fmt.Errorf("latest block has no EIP-1559 base fee")
	}
	tip, err = w.client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting priority fee: %w", err)
	}
	// 0.01 Gwei minimum prevents a near-zero RPC suggestion from removing priority.
	tip = new(big.Int).Set(tip)
	if tip.Cmp(big.NewInt(10_000_000)) < 0 {
		tip.SetInt64(10_000_000)
	}
	feeCap = new(big.Int).Mul(header.BaseFee, big.NewInt(2))
	feeCap.Add(feeCap, tip)
	return feeCap, tip, nil
}

func printGasCost(gasLimit uint64, gasPrice *big.Int) {
	priceGwei := new(big.Rat).SetFrac(gasPrice, big.NewInt(1_000_000_000))
	maxFee := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), gasPrice)
	feeETH := new(big.Rat).SetFrac(maxFee, big.NewInt(1_000_000_000_000_000_000))
	fmt.Printf("Gas limit: %d gas\nGas price (max): %s Gwei\nMaximum gas fee: %s ETH\n",
		gasLimit, priceGwei.FloatString(9), feeETH.FloatString(18))
}

func getUSDTDecimals(ctx context.Context, client Client, usdtABI abi.ABI, contractAddr common.Address) int64 {
	data, err := usdtABI.Pack("decimals")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to pack decimals call: %v\n", err)
		return 6 // fallback
	}
	callMsg := ethereum.CallMsg{To: &contractAddr, Data: data}
	res, err := client.CallContract(ctx, callMsg, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to get USDT decimals, using default 6: %v\n", err)
		return 6 // fallback
	}
	dec := new(big.Int).SetBytes(res)
	return dec.Int64()
}

func formatTokenAmount(amount *big.Int, decimals int64) string {
	f := new(big.Float).SetInt(amount)
	div := new(big.Float).SetFloat64(float64(1))
	for range decimals {
		div = new(big.Float).Mul(div, big.NewFloat(10))
	}
	val := new(big.Float).Quo(f, div)
	return val.Text('f', 6)
}
func (w *Wallet) LastTransactions(ctx context.Context, address string) error {
	if address == "" {
		address = w.cfg.Wallet
	}
	if !common.IsHexAddress(address) {
		return fmt.Errorf("invalid Ethereum address: %s", address)
	}
	client := w.client
	usdtABI, err := getUSDTABI()
	if err != nil {
		return err
	}
	contractAddr := common.HexToAddress(w.cfg.USDTContract)
	addr := common.HexToAddress(address)

	latestBlock, err := client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("error getting latest block: %w", err)
	}
	fromBlock := big.NewInt(0)
	if latestBlock > 5000 {
		fromBlock = new(big.Int).SetUint64(latestBlock - 5000)
	}
	transferTopic := usdtABI.Events["Transfer"].ID
	addressTopic := common.BytesToHash(addr.Bytes())
	// Indexed topics filter outgoing and incoming transfers at the node.
	filters := [][][]common.Hash{
		{{transferTopic}, {addressTopic}},
		{{transferTopic}, nil, {addressTopic}},
	}
	var txs []types.Log
	for _, topics := range filters {
		logs, err := client.FilterLogs(ctx, ethereum.FilterQuery{
			FromBlock: fromBlock,
			ToBlock:   new(big.Int).SetUint64(latestBlock),
			Addresses: []common.Address{contractAddr},
			Topics:    topics,
		})
		if err != nil {
			return fmt.Errorf("error fetching logs: %w", err)
		}
		for _, log := range logs {
			if len(log.Topics) >= 3 && !log.Removed {
				txs = append(txs, log)
			}
		}
	}
	sort.Slice(txs, func(i, j int) bool {
		if txs[i].BlockNumber != txs[j].BlockNumber {
			return txs[i].BlockNumber > txs[j].BlockNumber
		}
		return txs[i].Index > txs[j].Index
	})
	if len(txs) == 0 {
		fmt.Println("No USDT transactions found for this address in the last 5000 blocks.")
		return nil
	}
	decimals := getUSDTDecimals(ctx, client, usdtABI, contractAddr)
	seen := make(map[common.Hash]bool)
	count := 0
	for _, tx := range txs {
		if seen[tx.TxHash] {
			continue
		}
		seen[tx.TxHash] = true
		receipt, err := client.TransactionReceipt(ctx, tx.TxHash)
		if err != nil {
			return fmt.Errorf("error getting receipt for %s: %w", tx.TxHash.Hex(), err)
		}
		status := "Failed"
		if receipt.Status == types.ReceiptStatusSuccessful {
			status = "Success"
		}
		count++
		val := new(big.Int).SetBytes(tx.Data)
		fmt.Printf("#%d: Hash: %s\n  From: %s\n  To: %s\n  Value: %s USDT\n  Block: %d\n  Status: %s\n",
			count, tx.TxHash.Hex(), common.BytesToAddress(tx.Topics[1].Bytes()).Hex(),
			common.BytesToAddress(tx.Topics[2].Bytes()).Hex(), formatTokenAmount(val, decimals), tx.BlockNumber, status)
		if count == 3 {
			break
		}
	}
	return nil
}
func (w *Wallet) TransactionStatus(ctx context.Context, txHash string) error {
	hash, err := parseTransactionHash(txHash)
	if err != nil {
		return err
	}
	receipt, err := w.client.TransactionReceipt(ctx, hash)
	if errors.Is(err, ethereum.NotFound) {
		_, pending, lookupErr := w.client.TransactionByHash(ctx, hash)
		if lookupErr != nil {
			return fmt.Errorf("error finding transaction: %w", lookupErr)
		}
		if pending {
			fmt.Println("Status: Pending")
		} else {
			fmt.Println("Status: Awaiting receipt")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("error getting receipt: %w", err)
	}
	status := "Failed"
	if receipt.Status == types.ReceiptStatusSuccessful {
		status = "Success"
	}
	fmt.Printf("Status: %s\nBlock: %d\nGas Used: %d\n", status, receipt.BlockNumber.Uint64(), receipt.GasUsed)
	return nil
}

func (w *Wallet) SendUSDT(ctx context.Context, recipient, amountString string) error {
	amount, err := strconv.ParseFloat(amountString, 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %w", err)
	}
	// Validate recipient address
	if !common.IsHexAddress(recipient) {
		return fmt.Errorf("invalid Ethereum address: %s", recipient)
	}
	privKeyBytes, err := decryptKey(w.cfg.WalletKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	defer zeroBytes(privKeyBytes)

	client := w.client
	usdtABI, err := getUSDTABI()
	if err != nil {
		return err
	}
	usdtAddress := w.cfg.USDTContract
	contractAddr := common.HexToAddress(usdtAddress)

	// Decode hex key to raw bytes
	trimmed := strip0x(privKeyBytes)
	rawKey := make([]byte, hex.DecodedLen(len(trimmed)))
	_, err = hex.Decode(rawKey, trimmed)
	if err != nil {
		return fmt.Errorf("invalid private key hex: %w", err)
	}
	defer zeroBytes(rawKey)

	privateKey, err := crypto.ToECDSA(rawKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	fromAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce, err := client.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		return fmt.Errorf("error getting nonce: %w", err)
	}
	decimals := getUSDTDecimals(ctx, client, usdtABI, contractAddr)
	rawAmount := new(big.Float).Mul(big.NewFloat(amount), big.NewFloat(float64Pow(10, decimals)))
	amt := new(big.Int)
	rawAmount.Int(amt)
	feeCap, tipCap, err := w.suggestedDynamicFees(ctx)
	if err != nil {
		return err
	}

	input, err := usdtABI.Pack("transfer", common.HexToAddress(recipient), amt)
	if err != nil {
		return fmt.Errorf("error packing transfer: %w", err)
	}
	// Estimate gas
	msg := ethereum.CallMsg{
		From:      fromAddr,
		To:        &contractAddr,
		Gas:       0,
		GasFeeCap: feeCap,
		GasTipCap: tipCap,
		Value:     big.NewInt(0),
		Data:      input,
	}
	gasEstimate, err := client.EstimateGas(ctx, msg)
	if err != nil {
		return fmt.Errorf("error estimating gas: %w", err)
	}
	printGasCost(gasEstimate, feeCap)
	fmt.Printf("Priority fee: %s Gwei\n", new(big.Rat).SetFrac(tipCap, big.NewInt(1_000_000_000)).FloatString(9))

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: big.NewInt(1), Nonce: nonce, To: &contractAddr,
		Value: big.NewInt(0), Gas: gasEstimate,
		GasFeeCap: feeCap, GasTipCap: tipCap, Data: input,
	})
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(1)), privateKey)
	if err != nil {
		return fmt.Errorf("error signing tx: %w", err)
	}
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		return fmt.Errorf("error sending tx: %w", err)
	}
	fmt.Printf("Transaction sent! Tx Hash: %s\n", signedTx.Hash().Hex())
	return nil
}

func (w *Wallet) SendETH(ctx context.Context, recipient, amountString string) error {
	amount, err := strconv.ParseFloat(amountString, 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %w", err)
	}
	// Validate recipient address
	if !common.IsHexAddress(recipient) {
		return fmt.Errorf("invalid Ethereum address: %s", recipient)
	}
	privKeyBytes, err := decryptKey(w.cfg.WalletKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	defer zeroBytes(privKeyBytes)

	client := w.client

	// Decode hex key to raw bytes
	trimmed := strip0x(privKeyBytes)
	rawKey := make([]byte, hex.DecodedLen(len(trimmed)))
	_, err = hex.Decode(rawKey, trimmed)
	if err != nil {
		return fmt.Errorf("invalid private key hex: %w", err)
	}
	defer zeroBytes(rawKey)

	privateKey, err := crypto.ToECDSA(rawKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	fromAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce, err := client.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		return fmt.Errorf("error getting nonce: %w", err)
	}

	// Convert ETH to wei (1 ETH = 10^18 wei)
	ethToWei := new(big.Float).Mul(big.NewFloat(amount), big.NewFloat(1e18))
	value := new(big.Int)
	ethToWei.Int(value)

	feeCap, tipCap, err := w.suggestedDynamicFees(ctx)
	if err != nil {
		return err
	}

	// Estimate gas for simple ETH transfer
	toAddr := common.HexToAddress(recipient)
	msg := ethereum.CallMsg{
		From:      fromAddr,
		To:        &toAddr,
		Gas:       0,
		GasFeeCap: feeCap,
		GasTipCap: tipCap,
		Value:     value,
		Data:      nil,
	}
	gasEstimate, err := client.EstimateGas(ctx, msg)
	if err != nil {
		return fmt.Errorf("error estimating gas: %w", err)
	}
	printGasCost(gasEstimate, feeCap)
	fmt.Printf("Priority fee: %s Gwei\n", new(big.Rat).SetFrac(tipCap, big.NewInt(1_000_000_000)).FloatString(9))

	// Create transaction
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: big.NewInt(1), Nonce: nonce, To: &toAddr,
		Value: value, Gas: gasEstimate, GasFeeCap: feeCap, GasTipCap: tipCap,
	})

	// Sign transaction
	chainID := big.NewInt(1) // Mainnet
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		return fmt.Errorf("error signing transaction: %w", err)
	}

	// Send transaction
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		return fmt.Errorf("error sending transaction: %w", err)
	}

	fmt.Printf("ETH Transaction sent! Tx Hash: %s\n", signedTx.Hash().Hex())
	return nil
}

func float64Pow(a float64, b int64) float64 {
	res := 1.0
	for range b {
		res *= a
	}
	return res
}
func EncryptKeyPrompt() {
	fmt.Print("Enter PRIVATE KEY (hex): ")
	// Use ReadPassword to hide input and get bytes directly
	privKey, _ := term.ReadPassword(getStdinFD())
	fmt.Println()
	defer zeroBytes(privKey)

	// Trim whitespace/newlines if any (though ReadPassword usually just gets the chars)
	privKey = bytes.TrimSpace(privKey)

	fmt.Print("Enter password to encrypt PRIVATE KEY: ")
	bytePassword, _ := term.ReadPassword(getStdinFD())
	fmt.Println()
	defer zeroBytes(bytePassword)

	if len(privKey) == 0 || len(bytePassword) == 0 {
		fmt.Println("Private key and password must not be empty.")
		return
	}
	EncryptKey(privKey, bytePassword)
}
func EncryptKey(privKey, passphrase []byte) {
	salt := make([]byte, 16)
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		fmt.Println("Error generating salt:", err)
		return
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println("Error generating iv:", err)
		return
	}
	key, _ := scrypt.Key(passphrase, salt, 1<<15, 8, 1, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error creating cipher:", err)
		return
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error creating GCM:", err)
		return
	}
	ciphertext := aesgcm.Seal(nil, iv, privKey, nil)
	out := fmt.Sprintf("%x:%x:%x:%x", salt, iv, aesgcm.Overhead(), ciphertext)
	fmt.Println("Encrypted PRIVATE KEY: " + out)
}

func decryptKey(encryptedKey string) ([]byte, error) {
	fmt.Print("Enter password to decrypt PRIVATE KEY: ")
	bytePassword, _ := term.ReadPassword(getStdinFD())
	fmt.Println()
	defer zeroBytes(bytePassword)

	parts := strings.Split(strings.TrimSpace(encryptedKey), ":")
	if len(parts) != 4 {
		return nil, errors.New("priv key format invalid")
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("error decoding salt: %w", err)
	}
	iv, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding iv: %w", err)
	}
	ciphertext, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("error decoding ciphertext: %w", err)
	}
	key, err := scrypt.Key(bytePassword, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("error deriving key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return plaintext, nil
}

func (w *Wallet) ShowInfo() {
	privKeyBytes, err := decryptKey(w.cfg.WalletKey)
	if err == nil {
		defer zeroBytes(privKeyBytes)
		fmt.Println("key: [REDACTED FOR SECURITY]")
	} else {
		fmt.Println("key error:", err)
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func strip0x(b []byte) []byte {
	if len(b) >= 2 && b[0] == '0' && (b[1] == 'x' || b[1] == 'X') {
		return b[2:]
	}
	return b
}

// getStdinFD returns the file descriptor for stdin appropriate for the current platform
func getStdinFD() int {
	// On Windows, syscall.Stdin is uintptr, need to convert to int
	// On Unix-like systems, syscall.Stdin is int
	// nolint:unconvert // This conversion is necessary for Windows compatibility
	return int(syscall.Stdin)
}
