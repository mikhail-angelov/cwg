# cwg: Ethereum & USDT Wallet CLI
*(nodejs version is here: [https://github.com/mikhail-angelov/cw](https://github.com/mikhail-angelov/cw))*


A command-line wallet written in Go for managing Ethereum and USDT (Tether) on the Ethereum mainnet.
Features include wallet creation, balance checking, transaction history, USDT transfers, and secure private key encryption.

---

## Features

- **Create a new Ethereum wallet**
- **Check ETH and USDT balances**
- **Show last 3 USDT transactions for an address**
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

### Commands

- `create`
  Create a new Ethereum wallet.

- `balance <address>`
  Show ETH and USDT balances for the address (uses default if omitted).

- `last <address>`
  Show last 3 USDT transactions for the address.

- `status <txHash>`
  Show status of a transaction by hash.

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
  go run main.go last 0xYourAddress
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
