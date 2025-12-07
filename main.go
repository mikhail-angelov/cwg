package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// version is set during build via ldflags
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		printHelp()
		return 0
	}

	// Create a root context that listens for OS signals
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := LoadConfig("config.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		return 1
	}

	client, err := getClient(cfg.InfuraAPIKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing client: %v\n", err)
		return 1
	}
	defer client.Close()

	wallet := NewWallet(cfg, client)

	switch os.Args[1] {
	case "create":
		if err := wallet.CreateWallet(); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating wallet: %v\n", err)
			return 1
		}
	case "balance":
		address := ""
		if len(os.Args) > 2 {
			address = os.Args[2]
		}
		if err := wallet.CheckBalance(ctx, address); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking balance: %v\n", err)
			return 1
		}
	case "last":
		address := ""
		if len(os.Args) > 2 {
			address = os.Args[2]
		}
		if err := wallet.LastTransactions(ctx, address); err != nil {
			fmt.Fprintf(os.Stderr, "Error getting transactions: %v\n", err)
			return 1
		}
	case "status":
		if len(os.Args) < 3 {
			fmt.Println("Usage: status <txHash>")
			return 1
		}
		if err := wallet.TransactionStatus(ctx, os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error getting status: %v\n", err)
			return 1
		}
	case "send":
		if len(os.Args) < 4 {
			fmt.Println("Usage: send <recipient> <amount>")
			return 1
		}
		if err := wallet.SendUSDT(ctx, os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "Error sending USDT: %v\n", err)
			return 1
		}
	case "send-eth":
		if len(os.Args) < 4 {
			fmt.Println("Usage: send-eth <recipient> <amount>")
			return 1
		}
		if err := wallet.SendETH(ctx, os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "Error sending ETH: %v\n", err)
			return 1
		}
	case "encrypt-key":
		EncryptKeyPrompt()
	case "info":
		wallet.ShowInfo()
	default:
		printHelp()
	}
	return 0
}

func printHelp() {
	fmt.Printf("cw-go CLI v%s\n", version)
	fmt.Println(`	Usage:
	  create                Create new wallet
	  balance <address>     Check USDT and ETH balance
	  last <address>        Show last 3 USDT transactions for an address
	  status <txHash>       Show status of a transaction by hash
	  send <recipient> <amount>  Send USDT to an account
	  send-eth <recipient> <amount>  Send ETH to an account
	  info                  Show app info
	`)
}
