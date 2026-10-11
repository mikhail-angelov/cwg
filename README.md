# cwg: Ethereum & USDT Wallet CLI
*(nodejs version is here: [https://github.com/mikhail-angelov/cw](https://github.com/mikhail-angelov/cw))*


A command-line wallet written in Go for managing Ethereum and USDT (Tether) on the Ethereum mainnet.
Features include wallet creation, balance checking, transaction history, USDT transfers, and secure private key encryption.

---

## Features

- **Create a new Ethereum wallet**
- **Check ETH and USDT balances**
- **Show last 3 recent USDT transactions with status**
- **Send USDT to any Ethereum address**
- **Check transaction status**
- **Encrypt and decrypt private keys securely**
- **Configurable via `config.json`**

---

## Requirements

- Go 1.18+
- [Infura](https://infura.io/) API key (for Ethereum node access)
- USDT contract ABI file (`usdt-abi.json`)
- `config.json` file (see below)

---

## Setup

1. **Clone the repository**

   ```sh
   git clone <your-repo-url>
   cd cwg
   ```

2. **Install dependencies**

   ```sh
   go mod tidy
   ```

3. **Prepare `config.json`**

   Create a `config.json` file in the project root:

   ```json
   {
     "infura_api_key": "YOUR_INFURA_API_KEY",
     "etherscan_api_key": "YOUR_ETHERSCAN_API_KEY",
     "usd_contract": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
     "wallet": "YOUR_ETH_ADDRESS",
     "wallet_key": "YOUR_ENCRYPTED_PRIVATE_KEY"
   }
   ```

   - `usd_contract` should be the USDT contract address on Ethereum mainnet.
   - `wallet` and `wallet_key` can be left empty if you are creating a new wallet.

4. **Download the USDT ABI**

   Save the ERC20 ABI as `usdt-abi.json` in the project root.
   You can get the ABI from [Etherscan USDT Contract](https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7#code).

---

## Usage

```sh
go run main.go <command> [args...]
```

New ETH and USDT transfers use EIP-1559: the maximum gas price is twice the latest base fee plus the RPC-suggested priority fee (at least 0.01 Gwei). The actual fee depends on the base fee in the mined block and gas consumed. This does not change already pending transactions.

Sending and cancelling transactions use the same fee display: gas limit in gas units, maximum gas price in Gwei, and maximum network fee in ETH (gas limit × maximum gas price).

### Commands

- `create`
  Create a new Ethereum wallet.

- `balance <address>`
  Show ETH and USDT balances for the address (uses default if omitted).

- `last [address]`
  Show the last 3 distinct USDT transactions in the last 5000 blocks, newest first, with receipt status (`Success` or `Failed`). Uses the configured wallet if the address is omitted. Incoming and outgoing transfers are filtered by address at the RPC node. Pending and reverted transfers have no Transfer logs and are not included; use `status <txHash>` to check a known transaction.

- `status <txHash>`
  Show `Pending`, `Success`, or `Failed` for a transaction by hash.

- `cancel <txHash>`
  Attempt to cancel a pending transaction from your wallet by sending 0 ETH to yourself with the same nonce. Gas prices are raised by at least 25% and the fee cap is at least the current suggested gas price. Supports legacy, access-list, and EIP-1559 transactions on Ethereum mainnet. Prints the maximum gas fee before the password prompt and the replacement hash after sending. Cancellation is effective only when the replacement is mined first; check its hash with `status`. Gas is paid in ETH.

- `send <recipient> <amount>`
  Send USDT to a recipient address.

- `encrypt-key`
  Encrypt a private key for storage in `config.json`.

- `info`
  Show wallet info.

---

## Examples

- **Create a new wallet**
  ```sh
  go run main.go create
  ```

- **Check balances**
  ```sh
  go run main.go balance 0xYourAddress
  ```

- **Show last 3 USDT transactions**
  ```sh
  ./cwg last
  ./cwg last 0xYourAddress
  ```

- **Send USDT**
  ```sh
  go run main.go send 0xRecipientAddress 10.5
  ```

- **Encrypt a private key**
  ```sh
  go run main.go encrypt-key
  ```

---

## Security

- Private keys are encrypted using a password and stored in the config.
- Never share your private key or password.
- Always use strong, unique passwords for encryption.

---

## License

MIT

---
