package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

type Config struct {
	INFURA_API_KEY    string `json:"infura_api_key"`
	ETHERSCAN_API_KEY string `json:"etherscan_api_key"`
	USDT_CONTRACT     string `json:"usd_contract"`
	WALLET            string `json:"wallet"`
	WALLET_KEY        string `json:"wallet_key"`
}

type Wallet struct {
	cfg *Config
}

func NewWallet(json string) *Wallet {
	cfg, err := LoadConfig(json)
	if err != nil {
		fmt.Println("Failed to load config:", err)
		os.Exit(1)
	}
	return &Wallet{cfg: cfg}
}

func getClient(key string) *ethclient.Client {
	providerURL := "https://mainnet.infura.io/v3/" + key
	client, err := ethclient.Dial(providerURL)
	if err != nil {
		fmt.Println("Error connecting to Ethereum:", err)
		os.Exit(1)
	}
	return client
}

func getUSDTABI() abi.ABI {
	abiBytes, err := os.ReadFile(usdtABIPath)
	if err != nil {
		fmt.Println("Error reading ABI:", err)
		os.Exit(1)
	}
	usdtABI, err := abi.JSON(strings.NewReader(string(abiBytes)))
	if err != nil {
		fmt.Println("Error parsing ABI:", err)
		os.Exit(1)
	}
	return usdtABI
}

func (w *Wallet) CreateWallet() {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Printf("New Wallet:\nAddress: %s\nPrivate Key: %x\n", address.Hex(), crypto.FromECDSA(privateKey))
}
func (w *Wallet) CheckBalance(address string) {
	if address == "" {
		address = w.cfg.WALLET
	}
	fmt.Println("Balance for: ", address)
	client := getClient(w.cfg.INFURA_API_KEY)
	defer client.Close()

	if !common.IsHexAddress(address) {
		fmt.Println("Invalid Ethereum address:", address)
		return
	}
	addr := common.HexToAddress(address)

	// ETH Balance
	ethBalance, err := client.BalanceAt(context.Background(), addr, nil)
	if err != nil {
		fmt.Println("Error getting ETH balance:", err)
		return
	}
	fmt.Printf("ETH Balance: %s (%s)\n", weiToEther(ethBalance), address)

	// USDT Balance
	usdtABI := getUSDTABI()
	usdtAddress := w.cfg.USDT_CONTRACT
	contractAddr := common.HexToAddress(usdtAddress)
	data, err := usdtABI.Pack("balanceOf", addr)
	if err != nil {
		fmt.Println("Error packing balanceOf:", err)
		return
	}
	callMsg := ethereum.CallMsg{To: &contractAddr, Data: data}
	res, err := client.CallContract(context.Background(), callMsg, nil)
	if err != nil {
		fmt.Println("Error calling contract:", err)
		return
	}
	balance := new(big.Int).SetBytes(res)
	decimals := getUSDTDecimals(client, usdtABI, contractAddr)
	fmt.Printf("USDT Balance: %s (%s)\n", formatTokenAmount(balance, decimals), address)
}

func weiToEther(wei *big.Int) string {
	f := new(big.Float).SetInt(wei)
	ethValue := new(big.Float).Quo(f, big.NewFloat(1e18))
	return ethValue.Text('f', 6)
}

func getUSDTDecimals(client *ethclient.Client, usdtABI abi.ABI, contractAddr common.Address) int64 {
	data, _ := usdtABI.Pack("decimals")
	callMsg := ethereum.CallMsg{To: &contractAddr, Data: data}
	res, err := client.CallContract(context.Background(), callMsg, nil)
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
func (w *Wallet) LastTransactions(address string) {
	client := getClient(w.cfg.INFURA_API_KEY)
	defer client.Close()
	usdtABI := getUSDTABI()
	usdtAddress := w.cfg.USDT_CONTRACT
	contractAddr := common.HexToAddress(usdtAddress)
	addr := common.HexToAddress(address)

	// Get latest block
	latestBlock, err := client.BlockNumber(context.Background())
	if err != nil {
		fmt.Println("Error getting latest block:", err)
		return
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
	logs, err := client.FilterLogs(context.Background(), query)
	if err != nil {
		fmt.Println("Error fetching logs:", err)
		return
	}
	decimals := getUSDTDecimals(client, usdtABI, contractAddr)
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
		return
	}
	for i := n - 1; i >= 0 && i >= n-3; i-- {
		tx := txs[i]
		val := new(big.Int).SetBytes(tx.Data)
		fmt.Printf("#%d: Hash: %s\n  From: %s\n  To: %s\n  Value: %s USDT\n  Block: %d\n",
			n-i, tx.TxHash.Hex(), tx.Topics[1].Hex(), tx.Topics[2].Hex(), formatTokenAmount(val, decimals), tx.BlockNumber)
	}
}
func (w *Wallet) TransactionStatus(txHash string) {
	client := getClient(w.cfg.INFURA_API_KEY)
	defer client.Close()
	hash := common.HexToHash(txHash)
	receipt, err := client.TransactionReceipt(context.Background(), hash)
	if err != nil {
		fmt.Println("Transaction not found or not yet mined.")
		return
	}
	fmt.Printf("Status: %v\nBlock: %d\nGas Used: %d\n", receipt.Status == 1, receipt.BlockNumber.Uint64(), receipt.GasUsed)
}

func (w *Wallet) SendUSDT(recipient string, amountString string) {
	amount, err := strconv.ParseFloat(amountString, 64)
	if err != nil {
		fmt.Println("Invalid amount:", err)
		return
	}
	privKeyHex, err := decryptKey(w.cfg.WALLET_KEY)
	if err != nil {
		fmt.Println("Failed to decrypt:", err)
		return
	}

	client := getClient(w.cfg.INFURA_API_KEY)
	defer client.Close()
	usdtABI := getUSDTABI()
	usdtAddress := w.cfg.USDT_CONTRACT
	contractAddr := common.HexToAddress(usdtAddress)
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		fmt.Println("Invalid private key:", err)
		return
	}
	fromAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddr)
	if err != nil {
		fmt.Println("Error getting nonce:", err)
		return
	}
	decimals := getUSDTDecimals(client, usdtABI, contractAddr)
	rawAmount := new(big.Float).Mul(big.NewFloat(amount), big.NewFloat(float64Pow(10, decimals)))
	amt := new(big.Int)
	rawAmount.Int(amt)
	auth := bind.NewKeyedTransactor(privateKey, big.NewInt(1))
	if err != nil {
		fmt.Println("Error creating transactor:", err)
		return
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(100000)
	gasPrice, _ := client.SuggestGasPrice(context.Background())
	auth.GasPrice = gasPrice

	input, err := usdtABI.Pack("transfer", common.HexToAddress(recipient), amt)
	if err != nil {
		fmt.Println("Error packing transfer:", err)
		return
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
	gasEstimate, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		fmt.Println("Error estimating gas:", err)
		return
	}
	fmt.Printf("Estimated Gas: %d\n", gasEstimate)
	auth.GasLimit = gasEstimate

	tx := types.NewTransaction(nonce, contractAddr, big.NewInt(0), auth.GasLimit, auth.GasPrice, input)
	signedTx, err := auth.Signer(fromAddr, tx)
	if err != nil {
		fmt.Println("Error signing tx:", err)
		return
	}
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		fmt.Println("Error sending tx:", err)
		return
	}
	fmt.Printf("Transaction sent! Tx Hash: %s\n", signedTx.Hash().Hex())
}
func float64Pow(a float64, b int64) float64 {
	res := 1.0
	for i := int64(0); i < b; i++ {
		res *= a
	}
	return res
}
func EncryptKeyPrompt() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter PRIVATE KEY (hex): ")
	privKey, _ := reader.ReadString('\n')
	privKey = strings.TrimSpace(privKey)

	fmt.Print("Enter password to encrypt PRIVATE KEY: ")
	bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	password := string(bytePassword)

	if privKey == "" || password == "" {
		fmt.Println("Private key and password must not be empty.")
		return
	}
	EncryptKey(privKey, password)
}
func EncryptKey(privKey, passphrase string) {
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
	key, _ := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
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
	ciphertext := aesgcm.Seal(nil, iv, []byte(privKey), nil)
	out := fmt.Sprintf("%x:%x:%x:%x", salt, iv, aesgcm.Overhead(), ciphertext)
	fmt.Println("Encrypted PRIVATE KEY: " + out)
}

func decryptKey(encryptedKey string) (string, error) {
	fmt.Print("Enter password to encrypt PRIVATE KEY: ")
	bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	password := string(bytePassword)
	parts := strings.Split(strings.TrimSpace(encryptedKey), ":")
	if len(parts) != 4 {
		return "", errors.New("priv key format invalid")
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("error decoding salt: %w", err)
	}
	iv, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("error decoding iv: %w", err)
	}
	ciphertext, err := hex.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("error decoding ciphertext: %w", err)
	}
	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("error deriving key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM: %w", err)
	}
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(plaintext), nil
}

func (w *Wallet) ShowInfo() {
	privKeyHex, err := decryptKey(w.cfg.WALLET_KEY)
	fmt.Println("key:", privKeyHex)
	fmt.Println("key:", err)
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
