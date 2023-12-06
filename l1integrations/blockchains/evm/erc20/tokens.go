package erc20

import (
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/metachris/eth-go-bindings/erc20"
)

type TokenDescription struct {
	BlockchainID uint
	Address      string
	Symbol       string
	Name         string
}

var (
	Polygon_WMatic = TokenDescription{BlockchainID: 137, Address: "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", Symbol: "Matic", Name: "Matic Network(Polygon)"}
	Polygon_UNI    = TokenDescription{BlockchainID: 137, Address: "0xb33EaAd8d922B1083446DC23f610c2567fB5180f", Symbol: "UNI", Name: "UNISwap Token"}
	Polygon_AMP    = TokenDescription{BlockchainID: 137, Address: "0x0621d647cecbFb64b79E44302c1933cB4f27054d", Symbol: "AMP", Name: "Amp"}
	Polygon_USDC   = TokenDescription{BlockchainID: 137, Address: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", Symbol: "USDC", Name: "USD Coin"}
	Polygon_USDT   = TokenDescription{BlockchainID: 137, Address: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", Symbol: "USDT", Name: "USD Tether"}
	Polygon_AGIX   = TokenDescription{BlockchainID: 137, Address: "0x190Eb8a183D22a4bdf278c6791b152228857c033", Symbol: "AGIX", Name: "SingularityNET Token"}

	Tokens []TokenDescription = []TokenDescription{
		Polygon_WMatic,
		Polygon_UNI,
		Polygon_AMP,
		Polygon_USDC,
		Polygon_USDT,
		Polygon_AGIX}
)

func GetToken(blockChainID uint, symbol string) (TokenDescription, error) {
	for _, token := range Tokens {
		if token.BlockchainID == blockChainID && token.Symbol == symbol {
			return token, nil
		}
	}

	return TokenDescription{}, fmt.Errorf("don't ever try to get a token that is not there: %d, %s", blockChainID, symbol)
}

func GetTokenByAddress(blockChainID uint, address string) (TokenDescription, error) {
	for _, token := range Tokens {
		if token.BlockchainID == blockChainID && token.Address == address {
			return token, nil
		}
	}

	return TokenDescription{}, fmt.Errorf("don't ever try to get a token that is not there: %d, %s", blockChainID, address)
}

func GetTokenDecimal(erc20Address common.Address, client *ethclient.Client) (uint8, error) {
	var decimals uint8
	token, err := erc20.NewErc20(erc20Address, client)
	if err != nil {
		return decimals, err
	}

	decimals, err = token.Decimals(&bind.CallOpts{})
	if err != nil {
		return decimals, err
	}

	return decimals, nil
}
