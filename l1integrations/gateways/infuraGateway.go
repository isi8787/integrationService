package gateways

import (
	"finco/l1integration/common"

	"github.com/ethereum/go-ethereum/ethclient"
	log "github.com/sirupsen/logrus"
)

// InfuraETHClient common client for transactions being submited using Infura
// This will be for ETH and ERC20 tokens
func InfuraETHClient() *ethclient.Client {
	var network string
	if common.GloabalENVVars.WorkingEnvironment == "development" {
		network = common.L1Configurations.Infura.Goerli
	} else if common.GloabalENVVars.WorkingEnvironment == "production" {
		network = common.L1Configurations.Infura.Mainnet
	}

	client, err := ethclient.Dial(network) // TODO: need configuration or env variable for sensitive data
	if err != nil {
		log.Fatal(err)
	}

	return client
}
