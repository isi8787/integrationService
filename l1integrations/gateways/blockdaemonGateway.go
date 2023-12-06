package gateways

import (
	"errors"
	"finco/l1integration/common"
	"fmt"
	"os"
	"time"

	ubiquity "gitlab.com/Blockdaemon/ubiquity/ubiquity-go-client/v1/pkg/client"
	ubiquityWs "gitlab.com/Blockdaemon/ubiquity/ubiquity-go-client/v1/pkg/ws"
)

/**
Submitting a transaction and waiting for its confirmation.
*Important* for BTC, any amount left after sending to destination and change addresses is automatically paid as fee.

Env variables:
	1) UBI_ACCESS_TOKEN - required, Ubiquity API Access Token
	2) UBI_ENDPOINT - optional, Ubiquity API custom endpoint (prod by default)
	3) UBI_PLATFORM - optional, platform e.g. ethereum (bitcoin by default)
*/

const (
	txWaitDuration = 15 * time.Minute
)

// GetAccessToken retrieve blockdaemon token
func GetAccessToken() string {
	// Access token is required
	accessToken := os.Getenv(common.UBIAccessToken)
	if accessToken == "" {
		panic(fmt.Errorf("env variable '%s' must be set", common.UBIAccessToken))
	}
	return accessToken
}

// BlockDaemonConnect creates a blockdaemon client
func BlockDaemonConnect() *ubiquity.APIClient {
	// You can *optionally* set a custom endpoint or it will use prod
	config := ubiquity.NewConfiguration()
	if endpoint := os.Getenv("UBI_ENDPOINT"); endpoint != "" {
		config.Servers = ubiquity.ServerConfigurations{
			{
				URL:         endpoint,
				Description: "Custom endpoint",
			},
		}
	}

	// Creating client
	apiClient := ubiquity.NewAPIClient(config)

	return apiClient
}

// waitForTxConfirmation creates a websocket to await transaction response for submitted transactions
func waitForTxConfirmation(wsClient *ubiquityWs.Client, address, txID string) {
	subID, txs, err := wsClient.SubscribeTxs(&ubiquityWs.TxsFilter{Addresses: []string{address}})
	if err != nil {
		panic(fmt.Errorf("failed to subscribe to transactions: %v", err))
	}
	fmt.Println("Subscribed for transactions of address", address)

	startedAt := time.Now()
	fmt.Println("Waiting for transaction confirmation...")
	newBlocks := make(map[string]bool) // This is just for fancy output
	for {
		select {
		case tx, ok := <-txs:
			if !ok {
				// The subscription would close if we close a client or get disconnected
				panic(errors.New("the subscription was closed"))
			}

			blockId := tx.GetBlockId()
			if !newBlocks[blockId] {
				newBlocks[blockId] = true
				fmt.Printf("Got new block #%s, checking...\n", blockId)
			}

			if tx.GetId() == txID {
				fmt.Printf("Transaction was confirmed under block #%s!\n", blockId)
				// Can be omitted if you close a client
				if err := wsClient.UnsubscribeTxs(subID); err != nil {
					panic(err)
				}
				return
			}
		case <-time.After(startedAt.Add(txWaitDuration).Sub(time.Now())):
			panic(fmt.Errorf("timed out while waiting for transaction confirmation"))
		}
	}
}
