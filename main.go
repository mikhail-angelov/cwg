package main

import (
	"fmt"
	"os"
)

func main() {

	if len(os.Args) < 2 {
		printHelp()
		return
	}
	wallet, err := NewWallet("config.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing wallet: %v\n", err)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "create":
		if err := wallet.CreateWallet(); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating wallet: %v\n", err)
			os.Exit(1)
		}
	case "balance":
		address := ""
		if len(os.Args) > 2 {
			address = os.Args[2]
		}
		if err := wallet.CheckBalance(address); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking balance: %v\n", err)
			os.Exit(1)
		}
	case "last":
		address := ""
		if len(os.Args) > 2 {
			address = os.Args[2]
		}
		if err := wallet.LastTransactions(address); err != nil {
			fmt.Fprintf(os.Stderr, "Error getting transactions: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if len(os.Args) < 3 {
			fmt.Println("Usage: status <txHash>")
			return
		}
		if err := wallet.TransactionStatus(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error getting status: %v\n", err)
			os.Exit(1)
		}
	case "send":
		if len(os.Args) < 4 {
			fmt.Println("Usage: send <recipient> <amount>")
			return
		}
		if err := wallet.SendUSDT(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "Error sending USDT: %v\n", err)
			os.Exit(1)
		}
	case "encrypt-key":
		EncryptKeyPrompt()
	case "info":
		wallet.ShowInfo()
	default:
		printHelp()
	}
}

func printHelp() {
	fmt.Println(`cw-go CLI
	Usage:
	  create                Create new wallet
	  balance <address>     Check USDT and ETH balance
	  last <address>        Show last 3 USDT transactions for an address
	  status <txHash>       Show status of a transaction by hash
	  send <recipient> <amount>  Send USDT to an account
	  info             Show app info
	`)
}
