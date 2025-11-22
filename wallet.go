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
	"strconv"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
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

func NewWallet(cfg *Config, client Client) (*Wallet, error) {
	return &Wallet{cfg: cfg, client: client}, nil
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
		address = w.cfg.WALLET
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
	usdtAddress := w.cfg.USDT_CONTRACT
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

func getUSDTDecimals(ctx context.Context, client Client, usdtABI abi.ABI, contractAddr common.Address) int64 {
	data, _ := usdtABI.Pack("decimals")
	callMsg := ethereum.CallMsg{To: &contractAddr, Data: data}
	res, err := client.CallContract(ctx, callMsg, nil)
	if err != nil {
		return 6 // fallback
	}
	dec := new(big.Int).SetBytes(res)
	return dec.Int64()
}

func formatTokenAmount(amount *big.Int, decimals int64) string {
	f := new(big.Float).SetInt(amount)
	div := new(big.Float).SetFloat64(float64(1))
	for i := int64(0); i < decimals; i++ {
		div = new(big.Float).Mul(div, big.NewFloat(10))
	}
	val := new(big.Float).Quo(f, div)
	return val.Text('f', 6)
}
func (w *Wallet) LastTransactions(ctx context.Context, address string) error {
	client := w.client
	usdtABI, err := getUSDTABI()
	if err != nil {
		return err
	}
	usdtAddress := w.cfg.USDT_CONTRACT
	contractAddr := common.HexToAddress(usdtAddress)
	addr := common.HexToAddress(address)

	// Get latest block
	latestBlock, err := client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("error getting latest block: %w", err)
	}
	fromBlock := big.NewInt(0)
	if latestBlock > 5000 {
		fromBlock = big.NewInt(int64(latestBlock - 5000))
	}
	// Transfer event signature
	event := usdtABI.Events["Transfer"]
	topic := event.ID

	query := ethereum.FilterQuery{
		FromBlock: fromBlock,
		ToBlock:   nil,
		Addresses: []common.Address{contractAddr},
		Topics:    [][]common.Hash{{topic}},
	}
	logs, err := client.FilterLogs(ctx, query)
	if err != nil {
		return fmt.Errorf("error fetching logs: %w", err)
	}
	decimals := getUSDTDecimals(ctx, client, usdtABI, contractAddr)
	var txs []types.Log
	for _, vLog := range logs {
		if len(vLog.Topics) < 3 {
			continue
		}
		from := common.HexToAddress(vLog.Topics[1].Hex())
		to := common.HexToAddress(vLog.Topics[2].Hex())
		if from == addr || to == addr {
			txs = append(txs, vLog)
		}
	}
	n := len(txs)
	if n == 0 {
		fmt.Println("No recent USDT transactions found for this address.")
		return nil
	}
	for i := n - 1; i >= 0 && i >= n-3; i-- {
		tx := txs[i]
		val := new(big.Int).SetBytes(tx.Data)
		fmt.Printf("#%d: Hash: %s\n  From: %s\n  To: %s\n  Value: %s USDT\n  Block: %d\n",
			n-i, tx.TxHash.Hex(), tx.Topics[1].Hex(), tx.Topics[2].Hex(), formatTokenAmount(val, decimals), tx.BlockNumber)
	}
	return nil
}
func (w *Wallet) TransactionStatus(ctx context.Context, txHash string) error {
	client := w.client
	hash := common.HexToHash(txHash)
	receipt, err := client.TransactionReceipt(ctx, hash)
	if err != nil {
		return fmt.Errorf("transaction not found or not yet mined")
	}
	fmt.Printf("Status: %v\nBlock: %d\nGas Used: %d\n", receipt.Status == 1, receipt.BlockNumber.Uint64(), receipt.GasUsed)
	return nil
}

func (w *Wallet) SendUSDT(ctx context.Context, recipient string, amountString string) error {
	amount, err := strconv.ParseFloat(amountString, 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %w", err)
	}
	privKeyBytes, err := decryptKey(w.cfg.WALLET_KEY)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	defer zeroBytes(privKeyBytes)

	client := w.client
	usdtABI, err := getUSDTABI()
	if err != nil {
		return err
	}
	usdtAddress := w.cfg.USDT_CONTRACT
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
	auth := bind.NewKeyedTransactor(privateKey, big.NewInt(1))
	if err != nil {
		return fmt.Errorf("error creating transactor: %w", err)
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(100000)
	gasPrice, _ := client.SuggestGasPrice(ctx)
	auth.GasPrice = gasPrice

	input, err := usdtABI.Pack("transfer", common.HexToAddress(recipient), amt)
	if err != nil {
		return fmt.Errorf("error packing transfer: %w", err)
	}
	// Estimate gas
	msg := ethereum.CallMsg{
		From:     fromAddr,
		To:       &contractAddr,
		Gas:      0,
		GasPrice: gasPrice,
		Value:    big.NewInt(0),
		Data:     input,
	}
	gasEstimate, err := client.EstimateGas(ctx, msg)
	if err != nil {
		return fmt.Errorf("error estimating gas: %w", err)
	}
	fmt.Printf("Estimated Gas: %d\n", gasEstimate)
	auth.GasLimit = gasEstimate

	tx := types.NewTransaction(nonce, contractAddr, big.NewInt(0), auth.GasLimit, auth.GasPrice, input)
	signedTx, err := auth.Signer(fromAddr, tx)
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
func float64Pow(a float64, b int64) float64 {
	res := 1.0
	for i := int64(0); i < b; i++ {
		res *= a
	}
	return res
}
func EncryptKeyPrompt() {
	fmt.Print("Enter PRIVATE KEY (hex): ")
	// Use ReadPassword to hide input and get bytes directly
	privKey, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	defer zeroBytes(privKey)

	// Trim whitespace/newlines if any (though ReadPassword usually just gets the chars)
	privKey = bytes.TrimSpace(privKey)

	fmt.Print("Enter password to encrypt PRIVATE KEY: ")
	bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
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
	bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
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
	privKeyBytes, err := decryptKey(w.cfg.WALLET_KEY)
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


