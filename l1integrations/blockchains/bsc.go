package blockchains

import (
	"crypto/ecdsa"
	"finco/l1integration/blockchains/evm"
	l1common "finco/l1integration/common"
	"finco/l1integration/gateways"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
)

var bscGatewayUrl = l1common.L1Configurations.BSC.Testnet
var bscChainIDInt = l1common.L1Configurations.ChainIDs.BSC.TestNet

func BNBTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	chainID := big.NewInt(bscChainIDInt)
	bsc := evm.EthereumLikeChainsFee{evm.BscScanUrl, evm.BscScanApiKey}
	gasLimit := bsc.GetBasicTxGasLimit()
	txCreator, err := evm.NewEVMTxCreator(chainID, bscGatewayUrl, gateways.DB.Ethereum, gateways.DB.Transactions, gasLimit.Uint64(), tx.BlockchainId)
	if err != nil {
		return tx, err
	}
	return txCreator.CreateEthereumBasedTx(tx, pubKeyK)
}

func CompleteBNBTx(txHash string, signature l1common.EcdsaSignature) (*types.Transaction, error) {
	chainID := big.NewInt(bscChainIDInt)
	txBroadCaster, err := evm.NewEVMTxBroadcaster(chainID, bscGatewayUrl, gateways.DB.Ethereum, gateways.DB.Transactions)
	if err != nil {
		return nil, err
	}
	return txBroadCaster.CompleteTx(txHash, signature)
}

func BEP20Tx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	// TODO: Need to configure BEP20 contracts and set their addreses
	scAddress := tx.SCAddress
	chainID := big.NewInt(bscChainIDInt)
	bsc := evm.EthereumLikeChainsFee{evm.BscScanUrl, evm.BscScanApiKey}
	gasLimit := bsc.GetERC20GasLimit()
	txCreator, err := evm.NewEVMTxCreator(chainID, bscGatewayUrl, gateways.DB.Ethereum, gateways.DB.Transactions, gasLimit.Uint64(), tx.BlockchainId)
	if err != nil {
		return tx, err
	}
	return txCreator.CreateTokenTransferTx(tx, pubKeyK, scAddress)
}

func BinanceUniSwapTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	return UniSwapTx(tx, pubKeyK, uint(bscChainIDInt), bscGatewayUrl)
}

func BinanceUniQuote(tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {
	return UniQuote(uint(bscChainIDInt), bscGatewayUrl, tokenInId, amount, tokenOutId)
}

func BinanceOneInchSwapTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	return UniSwapTx(tx, pubKeyK, uint(bscChainIDInt), bscGatewayUrl)
}
func BinanceOneInchQuote(tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {
	return OneInchQuote(uint(bscChainIDInt), bscGatewayUrl, tokenInId, amount, tokenOutId)
}
