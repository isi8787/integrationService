package blockchains

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"finco/l1integration/blockchains/evm"
	oneinch "finco/l1integration/blockchains/evm/1inch"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	evm_erc20 "finco/l1integration/blockchains/evm/erc20"
	"finco/l1integration/blockchains/evm/uni"

	"github.com/ava-labs/coreth/accounts/abi"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/go-resty/resty/v2"
	"github.com/metachris/eth-go-bindings/erc20"
	log "github.com/sirupsen/logrus"
)

var infuraURI string = l1common.L1Configurations.Infura.Goerli
var ethereumChianIDInt int64 = l1common.L1Configurations.ChainIDs.Ethereum.TestNet

func GetETHTxFee() uint64 {
	client, err := ethclient.Dial(infuraURI)
	if err != nil {
		log.Error(err)
		return 0
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		error := errors.BuildErrMsg(errors.ClientError, err)
		log.Error(error)
		return 0
	}

	return gasPrice.Uint64()
}

// ETHTx prepare transaction for sending ETH
func ETHTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	eth := evm.EthereumLikeChainsFee{evm.ApiUrl, evm.ApiKey}
	chainID := big.NewInt(ethereumChianIDInt)
	gasLimit := eth.GetBasicTxGasLimit()
	txCreator, err := evm.NewEVMTxCreator(chainID, infuraURI, gateways.DB.Ethereum, gateways.DB.Transactions, gasLimit.Uint64(), tx.BlockchainId)
	if err != nil {
		return tx, err
	}
	return txCreator.CreateEthereumBasedTx(tx, pubKeyK)
}

// ERC20Tx prepares a transaction associated with an ERC20 token
func ERC20Tx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	scAddress := tx.SCAddress
	chainID := big.NewInt(ethereumChianIDInt)
	eth := evm.EthereumLikeChainsFee{evm.ApiUrl, evm.ApiKey}
	gasLimit := eth.GetERC20GasLimit()
	txCreator, err := evm.NewEVMTxCreator(chainID, infuraURI, gateways.DB.Ethereum, gateways.DB.Transactions, gasLimit.Uint64(), tx.BlockchainId)
	if err != nil {
		return tx, err
	}
	return txCreator.CreateTokenTransferTx(tx, pubKeyK, scAddress)
}

func UniSwapTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey, blockChainIDInt uint, uri string) (l1common.BasicTx, error) {
	tokenIn, err := evm_erc20.GetToken(blockChainIDInt, tx.TokenId)
	if err != nil {
		return tx, err
	}
	tokenOut, err := evm_erc20.GetTokenByAddress(blockChainIDInt, tx.ToAddress)
	if err != nil {
		return tx, err
	}

	blockChainIDBigInt := big.NewInt(int64(blockChainIDInt))
	eth := evm.EthereumLikeChainsFee{evm.ApiUrl, evm.ApiKey}
	gasLimit := eth.GetUniSwapGasLimit()
	txCreator, err := evm.NewEVMTxCreator(blockChainIDBigInt, uri, gateways.DB.Ethereum, gateways.DB.Transactions, gasLimit.Uint64(), tx.BlockchainId)
	if err != nil {
		return tx, err
	}
	return txCreator.CreateUniSwapTx(tx, pubKeyK, tokenIn, tokenOut)
}

func OneInchSwapTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey, blockChainIDInt uint, uri string) (l1common.BasicTx, error) {
	tokenIn, err := evm_erc20.GetToken(blockChainIDInt, tx.TokenId)
	if err != nil {
		return tx, err
	}
	tokenOut, err := evm_erc20.GetTokenByAddress(blockChainIDInt, tx.ToAddress)
	if err != nil {
		return tx, err
	}

	blockChainIDBigInt := big.NewInt(int64(blockChainIDInt))
	eth := evm.EthereumLikeChainsFee{evm.ApiUrl, evm.ApiKey}
	gasLimit := eth.GetUniSwapGasLimit()
	txCreator, err := evm.NewEVMTxCreator(blockChainIDBigInt, uri, gateways.DB.Ethereum, gateways.DB.Transactions, gasLimit.Uint64(), tx.BlockchainId)
	if err != nil {
		return tx, err
	}
	return txCreator.Create1inchSwapTx(tx, pubKeyK, tokenIn, tokenOut)
}

func EthereumUniSwapTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	return UniSwapTx(tx, pubKeyK, uint(ethereumChianIDInt), infuraURI)
}
func EthereumUniQuote(tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {
	return UniQuote(uint(ethereumChianIDInt), infuraURI, tokenInId, amount, tokenOutId)
}
func EthereumOneInchSwapTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	return OneInchSwapTx(tx, pubKeyK, uint(ethereumChianIDInt), infuraURI)
}
func EthereumOneInchQuote(tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {
	return OneInchQuote(uint(ethereumChianIDInt), infuraURI, tokenInId, amount, tokenOutId)
}

// ETH2Deposit prepares a transaction associated with the ethereum staking smart contract
func ETH2Deposit(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	fromAddress := crypto.PubkeyToAddress(pubKeyK)

	client, err := ethclient.Dial(infuraURI)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	// Shall use in that statement where tx broadcasted in blockchain for make shure.
	valueInEth, err := strconv.ParseFloat(tx.Value, 64)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	ethValue := big.NewFloat(valueInEth) // in wei (1 eth)

	ethTowei := big.NewFloat(1000000000000000000)

	var value = new(big.Float)
	value.Mul(ethValue, ethTowei)

	var intValue = new(big.Int)
	value.Int(intValue)

	eth := evm.EthereumLikeChainsFee{evm.ApiUrl, evm.ApiKey}
	gasValue, err := eth.GetProposeGasPrice()
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	gasLimit := eth.GetMinEthGasLimit()
	gasPrice := evm.GweiToWei(gasValue)

	contractAddress := common.HexToAddress(l1common.L1Configurations.Ethereum.StakingContract) // ETH2 deposit smart contract address
	data := common.FromHex(tx.Data)
	err = validateETHStake(data)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg("", err)
	}

	stakeTx := types.NewTransaction(nonce, contractAddress, intValue, gasLimit.Uint64(), gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Error(err)
	}

	chainID = big.NewInt(5) // TODO: use config file rather than hardcoding
	signereth := types.NewEIP155Signer(chainID)
	h := signereth.Hash(stakeTx)

	fullTxJSON, err := json.Marshal(stakeTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	intFee := eth.GetCalculatedGasFee(gasLimit, gasPrice)

	tx.FullTx = string(fullTxJSON)
	tx.TxHash = h.Hex()
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: h.Hex(), InputIndex: 0}}
	tx.Status = l1common.TxCreated
	tx.Fee, _ = WeiToEther(intFee).Float64()
	tx.Amount, _ = WeiToEther(intValue).Float64()

	err = gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil
}

// ETH2Deposit prepares a transaction associated with the ethereum staking smart contract
func ETHWCProcess(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	log.Info("ETHWCProcess: ", tx)
	fromAddress := crypto.PubkeyToAddress(pubKeyK)

	client, err := ethclient.Dial(infuraURI)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	// Shall use in that statement where tx broadcasted in blockchain for make shure.
	// Shall use in that statement where tx broadcasted in blockchain for make shure.
	valueInEth, err := strconv.ParseFloat(tx.Value, 64)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	ethValue := big.NewFloat(valueInEth) // in wei (1 eth)

	ethTowei := big.NewFloat(1000000000000000000)

	var value = new(big.Float)
	value.Mul(ethValue, ethTowei)

	var intValue = new(big.Int)
	value.Int(intValue)

	data := common.FromHex(tx.Data)
	toAddress := common.HexToAddress(tx.ToAddress)
	eth := evm.EthereumLikeChainsFee{evm.ApiUrl, evm.ApiKey}
	/* Deprecate since its not working due to etherscan not providng correct values for testnet
	gasPrice, err := eth.GetFastGasPrice()
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}
	*/
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	extraFast := new(big.Int).Mul(gasPrice, big.NewInt(2))

	msg := ethereum.CallMsg{
		From:     fromAddress,
		To:       &toAddress,
		Data:     data,
		Value:    intValue,
		GasPrice: extraFast,
	}

	minGas, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg("", err)
	}

	gasLimit := minGas // in units // minimum eth from etherscan for typical staking transactions

	stakeTx := types.NewTransaction(nonce, toAddress, intValue, gasLimit, extraFast, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Error(err)
	}

	chainID = big.NewInt(5) // TODO: use config file rather than hardcoding
	signereth := types.NewEIP155Signer(chainID)
	h := signereth.Hash(stakeTx)

	fullTxJSON, err := json.Marshal(stakeTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	intFee := eth.GetCalculatedGasFee(new(big.Int).SetUint64(gasLimit), gasPrice)

	tx.FullTx = string(fullTxJSON)
	tx.TxHash = h.Hex()
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: h.Hex(), InputIndex: 0}}
	tx.Status = l1common.TxCreated
	tx.Fee, _ = WeiToEther(intFee).Float64()
	tx.Amount, _ = WeiToEther(intValue).Float64()

	err = gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil
}

// CompleteTx provides single function for submiting transaction to infrastructure provider
// TODO: needs refactor once we support other blockchains beyond ethereum
func CompleteETHTx(txHash string, signature l1common.EcdsaSignature) (*types.Transaction, error) {
	chainID := big.NewInt(ethereumChianIDInt)
	txBroadCaster, err := evm.NewEVMTxBroadcaster(chainID, infuraURI, gateways.DB.Ethereum, gateways.DB.Transactions)
	if err != nil {
		return nil, err
	}
	return txBroadCaster.CompleteTx(txHash, signature)
}

func GetETHBalance(fromAddress common.Address) (*big.Int, error) {
	client, err := ethclient.Dial(infuraURI)
	if err != nil {
		return new(big.Int).SetUint64(0), errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	ethBalance, err := client.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		return new(big.Int).SetUint64(0), errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	return ethBalance, nil
}

// GetETHBalances support function to retrieve balances associated with
// an ETH address, including ERC20 tokens supported
func GetETHBalances(fromAddress common.Address) (l1common.ETHAccounts, error) {
	var result l1common.ETHAccounts

	result.Address = fromAddress.Hex()
	client, err := ethclient.Dial(infuraURI)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	ethBalance, err := client.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	result.Balance = WeiToEther(ethBalance).String()
	erc20map := make(map[string]string)
	for i, val := range l1common.Erc20Map {
		contractAddress := common.HexToAddress(val)
		token, err := erc20.NewErc20(contractAddress, client)
		if err != nil {
			return result, errors.BuildAndLogErrorMsg("", err)
		}

		bal, err := token.BalanceOf(&bind.CallOpts{}, fromAddress)
		if err != nil {
			return result, errors.BuildAndLogErrorMsg("", err)
		}

		decimals, err := token.Decimals(&bind.CallOpts{})
		if err != nil {
			return result, errors.BuildAndLogErrorMsg("", err)
		}

		erc20bal := new(big.Float).Quo(big.NewFloat(0).SetInt(bal), big.NewFloat(math.Pow10(int(decimals))))
		erc20map[i] = erc20bal.String()
	}

	result.ERC20Balances = erc20map

	return result, nil
}

// Support functions for converting between Ether and Wei
func EtherToWei(val *big.Int) *big.Int {
	return new(big.Int).Mul(val, big.NewInt(params.Ether))
}

func WeiToEther(val *big.Int) *big.Float {
	num := big.NewFloat(0).SetInt(val)
	dem := big.NewFloat(0).SetInt(big.NewInt(params.Ether))
	return big.NewFloat(0).Quo(num, dem)
}

// validateETHStake provides prevalidation of data sent to
// ETH2.0 staking smart contract
func validateETHStake(data []byte) error {
	//Total Input length
	if len(data) != 420 {
		return fmt.Errorf(fmt.Sprintf("Incorrect input lenght: %d expecting 420 bytes", len(data)))
	}

	// Get Method informaiton and input fields
	contractABI, err := GetContractABI(l1common.L1Configurations.Ethereum.StakingContract, l1common.L1Configurations.Ethereum.EtherscanAPIKEY)
	if err != nil {
		return fmt.Errorf("Error getting ABI:", err)
	}
	methodSigData := data[:4]
	inputsSigData := data[4:]
	method, err := contractABI.MethodById(methodSigData)
	if err != nil {
		log.Fatal(err)
		return err
	}
	inputsMap := make(map[string]interface{})
	err = method.Inputs.UnpackIntoMap(inputsMap, inputsSigData)
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.DecodeBodyError, err)
	}

	if method.Name != "deposit" {
		return fmt.Errorf("Incorrect method specified:", method.Name, "expecting deposit")
	}

	if _, ok := inputsMap["deposit_data_root"]; !ok {
		return fmt.Errorf("Missing input: deposit_data_root")
	}

	if _, ok := inputsMap["pubkey"]; !ok {
		return fmt.Errorf("Missing input: pubkey")
	}

	if _, ok := inputsMap["signature"]; !ok {
		return fmt.Errorf("Missing input: signature")
	}

	if _, ok := inputsMap["withdrawal_credentials"]; !ok {
		return fmt.Errorf("Missing input: withdrawal_credentials")
	}

	return nil
}

// for a given smart contract address extract supported functions and their inputs
func GetContractABI(contractAddress, etherscanAPIKey string) (*abi.ABI, error) {
	rawABIResponse, err := GetContractRawABI(contractAddress, etherscanAPIKey)
	if err != nil {
		return nil, err
	}

	contractABI, err := abi.JSON(strings.NewReader(*rawABIResponse.Result))
	if err != nil {
		return nil, err
	}
	return &contractABI, nil
}

// for a given smart contract address extract supported functions and their inputs
func GetContractRawABI(address string, apiKey string) (*RawABIResponse, error) {
	client := resty.New()
	rawABIResponse := &RawABIResponse{}
	resp, err := client.R().
		SetQueryParams(map[string]string{
			"module":  "contract",
			"action":  "getabi",
			"address": address,
			"apikey":  apiKey,
		}).
		SetResult(rawABIResponse).
		Get(l1common.L1Configurations.Ethereum.EtherscanURL)

	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf(fmt.Sprintf("Get contract raw abi failed: %s\n", resp))
	}
	if *rawABIResponse.Status != "1" {
		return nil, fmt.Errorf(fmt.Sprintf("Get contract raw abi failed: %s\n", *rawABIResponse.Result))
	}

	return rawABIResponse, nil
}

type (
	RawABIResponse struct {
		Status  *string `json:"status"`
		Message *string `json:"message"`
		Result  *string `json:"result"`
	}
)

func UniQuote(blockChainIDInt uint,
	uri string,
	tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {
	tokenIn, err := evm_erc20.GetToken(blockChainIDInt, tokenInId)
	if err != nil {
		return 0, err
	}
	tokenOut, err := evm_erc20.GetToken(blockChainIDInt, tokenOutId)
	if err != nil {
		return 0, err
	}

	client, err := ethclient.Dial(uri)
	if err != nil {
		return 0, err
	}

	return uni.GetRate(client, 100, tokenIn, amount, tokenOut)
}

func OneInchQuote(blockChainID uint,
	uri string,
	tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {

	tokenIn, err := evm_erc20.GetToken(blockChainID, tokenInId)
	if err != nil {
		return 0, err
	}

	tokenOut, err := evm_erc20.GetToken(blockChainID, tokenOutId)
	if err != nil {
		return 0, err
	}

	client, err := ethclient.Dial(uri)
	if err != nil {
		return 0, err
	}

	tokenInDecimal, err := evm_erc20.GetTokenDecimal(common.HexToAddress(tokenIn.Address), client)
	if err != nil {
		return 0, err
	}

	tokenOutDecimal, err := evm_erc20.GetTokenDecimal(common.HexToAddress(tokenOut.Address), client)
	if err != nil {
		return 0, err
	}

	bigFloatAmountIn := new(big.Float).SetFloat64(amount)
	bigAmountIn, _ := new(big.Float).Mul(bigFloatAmountIn, big.NewFloat(math.Pow10(int(tokenInDecimal)))).Int(nil)

	resp, err := oneinch.DoQuoteRequest(int64(blockChainID), tokenIn.Address, tokenOut.Address, bigAmountIn.String())
	if err != nil {
		return 0, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}

	bigFloatAmountOut, _ := new(big.Float).SetString(resp.ToTokenAmount)
	if bigFloatAmountOut == nil {
		return 0, errors.BuildAndLogErrorMsg(errors.HttpRequestError, fmt.Errorf("invalid number: %s", resp.ToTokenAmount))
	}
	amountOut, _ := new(big.Float).Mul(bigFloatAmountOut, big.NewFloat(math.Pow10(-int(tokenOutDecimal)))).Float64()
	return amountOut, nil
}
