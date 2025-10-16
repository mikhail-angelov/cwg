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
	wallet := NewWallet("config.json")

	switch os.Args[1] {
	case "create":
		wallet.CreateWallet()
	case "balance":
		address := ""
		if len(os.Args) > 2 {
			address = os.Args[2]
		}
		wallet.CheckBalance(address)
	case "last":
		address := ""
		if len(os.Args) > 2 {
			address = os.Args[2]
		}
		wallet.LastTransactions(address)
	case "status":
		if len(os.Args) < 3 {
			fmt.Println("Usage: status <txHash>")
			return
		}
		wallet.TransactionStatus(os.Args[2])
	case "send":
		if len(os.Args) < 4 {
			fmt.Println("Usage: send <recipient> <amount>")
			return
		}
		wallet.SendUSDT(os.Args[2], os.Args[3])
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
