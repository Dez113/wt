package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/caarlos0/env/v6"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
	"math/big"
)

var toAddress = common.HexToAddress("0x0664eFEb23fd7f2a7f160a85dE7eda07934A7e3f")
var contractAddress = common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7") // USDT

type Config struct {
	AlchemyMainnetAPIKey string `env:"ALCHEMY_KEY_MAINNET,required"`
	AlchemyHoleskyAPIKey string `env:"ALCHEMY_KEY_HOLESKY,required"`
	PrivateKey           string `env:"PRIVATE_KEY,required"`
}

func main() {
	cfg := Config{}
	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}

	err = env.Parse(&cfg)
	if err != nil {
		panic(err)

	}

	provider, err := ethclient.Dial(cfg.AlchemyMainnetAPIKey)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	if err = listenEvents(ctx, provider); err != nil {
		panic(err)
	}

	provider, err = ethclient.Dial(cfg.AlchemyHoleskyAPIKey)
	if err != nil {
		panic(err)
	}

	if err = transaction(ctx, provider, cfg.PrivateKey); err != nil {
		panic(err)
	}
}

func listenEvents(ctx context.Context, provider *ethclient.Client) error {
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddress},
	}

	logs := make(chan types.Log)
	sub, err := provider.SubscribeFilterLogs(ctx, query, logs) // not working  via https connection
	if err != nil {
		return fmt.Errorf("provider.SubscribeFilterLogs: %w", err)
	}

	blocksToListen := 3
	currentBlockNumber := uint64(0)
	eventCounter := 0
	blockCounter := 0

Listening:
	for {
		select {
		case err := <-sub.Err():
			return fmt.Errorf("provider.SubscribeFilterLogs: %w", err)
		case vLog := <-logs:
			if vLog.Removed {
				continue
			}

			if currentBlockNumber != vLog.BlockNumber {
				fmt.Println("blockNumber: ", vLog.BlockNumber, " events: ", eventCounter)
				eventCounter = 0
				currentBlockNumber = vLog.BlockNumber
				blockCounter++

				if blockCounter >= blocksToListen {
					break Listening
				}

				continue
			}

			eventCounter++
		}
	}

	return nil
}

func transaction(ctx context.Context, provider *ethclient.Client, pKey string) error {
	privateKey, err := crypto.HexToECDSA(pKey)
	if err != nil {
		return fmt.Errorf("crypto.HexToECDSA: %v", err)
	}

	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	value := big.NewInt(100000000000000000) //  0.1 eth

	balance, err := provider.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		return fmt.Errorf("provider.BalanceAt: %w", err)
	}

	if balance.Cmp(value) < 0 {
		return fmt.Errorf("insufficient balance")
	}

	nonce, err := provider.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return fmt.Errorf("ChainID: %v", err)
	}

	gasPrice, err := provider.SuggestGasPrice(context.Background())
	if err != nil {
		return fmt.Errorf("ChainID: %v", err)
	}

	txData := types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      uint64(21000), // minimal gas
		To:       &toAddress,
		Value:    value,
	}

	chainID, err := provider.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("ChainID: %v", err)
	}

	signedTx, err := types.SignTx(
		types.NewTx(&txData),
		types.NewEIP155Signer(chainID),
		privateKey,
	)
	if err != nil {
		return fmt.Errorf("types.SignTx: %v", err)
	}

	err = provider.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return fmt.Errorf("provider.SendTransaction: %v", err)
	}

	fmt.Printf("tx sent: %s", signedTx.Hash().Hex())

	return nil
}
