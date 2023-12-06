package blockchains

import (
	"crypto/ecdsa"
	"finco/l1integration/blockchains/evm"
	l1common "finco/l1integration/common"
	"finco/l1integration/gateways"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
)

var infuraURIPolygon = l1common.L1Configurations.Polygon.Testnet
var polygonChinIDInt = l1common.L1Configurations.ChainIDs.Polygon.TestNet

func PolygonTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	chainID := big.NewInt(polygonChinIDInt)
	plg := evm.EthereumLikeChainsFee{evm.PolygonScanUrl, evm.PolygonScanApiKey}
	gasLimit := plg.GetBasicTxGasLimit()
	txCreator, err := evm.NewEVMTxCreator(chainID, infuraURIPolygon, gateways.DB.Ethereum, gateways.DB.Transactions, gasLimit.Uint64(), tx.BlockchainId)
	if err != nil {
		return tx, err
	}
	return txCreator.CreateEthereumBasedTx(tx, pubKeyK)
}

func CompletePolygonTx(txHash string, signature l1common.EcdsaSignature) (*types.Transaction, error) {
	chainID := big.NewInt(polygonChinIDInt)
	txBroadCaster, err := evm.NewEVMTxBroadcaster(chainID, infuraURIPolygon, gateways.DB.Ethereum, gateways.DB.Transactions)
	if err != nil {
		return nil, err
	}
	return txBroadCaster.CompleteTx(txHash, signature)
}

func MATICTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	scAddress := l1common.Erc20Map[tx.TokenId]
	chainID := big.NewInt(polygonChinIDInt)
	plg := evm.EthereumLikeChainsFee{evm.PolygonScanUrl, evm.PolygonScanApiKey}
	gasLimit := plg.GetERC20GasLimit()
	txCreator, err := evm.NewEVMTxCreator(chainID, infuraURIPolygon, gateways.DB.Ethereum, gateways.DB.Transactions, gasLimit.Uint64(), tx.BlockchainId)
	if err != nil {
		return tx, err
	}
	return txCreator.CreateTokenTransferTx(tx, pubKeyK, scAddress)
}

func PolygonUniSwapTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	return UniSwapTx(tx, pubKeyK, uint(polygonChinIDInt), infuraURIPolygon)
}
func PolygonUniQuote(tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {
	return UniQuote(uint(polygonChinIDInt), infuraURIPolygon, tokenInId, amount, tokenOutId)
}
func PolygonOneInchSwapTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	return UniSwapTx(tx, pubKeyK, uint(polygonChinIDInt), infuraURIPolygon)
}
func PolygonOneInchQuote(tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {
	return OneInchQuote(uint(polygonChinIDInt), infuraURIPolygon, tokenInId, amount, tokenOutId)
}
