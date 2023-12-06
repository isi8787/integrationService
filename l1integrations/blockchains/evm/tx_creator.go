package evm

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	oneinch "finco/l1integration/blockchains/evm/1inch"
	evm_erc20 "finco/l1integration/blockchains/evm/erc20"
	"finco/l1integration/blockchains/evm/uni"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"
	"fmt"
	"math"
	"math/big"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/sha3"
)

type EVMTxCreator struct {
	ChianID  *big.Int
	gateways evmGateways
	gasLimit uint64
	gasPrice *big.Int
}

func NewEVMTxCreator(chainId *big.Int, nodeUrl string, nonceCollection *mongo.Collection, txsCollection *mongo.Collection, gasLimit uint64, chainName string) (*EVMTxCreator, error) {
	gasprices, err := GetFeesDB()
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	gasprice := getField(&gasprices, chainName)

	weiGasPrice := GweiToWei(gasprice.FastFee)
	evm := &EVMTxCreator{
		ChianID:  chainId,
		gasLimit: gasLimit,
		gasPrice: weiGasPrice,
	}

	eg, err := NewEvmGateways(nodeUrl, nonceCollection, txsCollection)
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}
	evm.gateways = eg

	return evm, nil
}

func (evm *EVMTxCreator) CreateEthereumBasedTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	log.Info("Creating Ethereum based transaction for", tx)
	fromAddress := crypto.PubkeyToAddress(pubKeyK)
	currentNonce, err := evm.getPendingNonceFor(fromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	gasprices, err := GetFeesDB()
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	gasPrice := getField(&gasprices, tx.BlockchainId)

	eth := EthereumLikeChainsFee{ApiUrl, ApiKey}
	fee := eth.GetCalculatedGasFee(new(big.Int).SetUint64(evm.gasLimit), gasPrice.FastFee)

	balance, err := evm.getBalanceFor(fromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	amount, err := convertToMinorValue(tx.Value)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	if balance.Cmp(amount) < 0 {
		insufficientBalanceError := fmt.Errorf("the balance of the account is not sufficient: the current balance is %v, the request value to transfer is %v", balance, amount)
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, insufficientBalanceError)
	} else if new(big.Int).Add(amount, fee).Cmp(balance) > 0 {
		amount.Sub(amount, fee)
	}

	toAddress := common.HexToAddress(tx.ToAddress)
	var data []byte
	fullTx := types.NewTransaction(currentNonce, toAddress, amount, evm.gasLimit, evm.gasPrice, data)

	signereth := types.NewEIP155Signer(evm.ChianID)
	h := signereth.Hash(fullTx)

	fullTxJSON, err := marshalToJson(fullTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	tx.FullTx = string(fullTxJSON)
	tx.TxHash = h.Hex()
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: h.Hex(), InputIndex: 0}}
	tx.Status = l1common.TxCreated
	tx.Fee, _ = convertToMajorValue(fee).Float64()
	tx.Amount, _ = convertToMajorValue(amount).Float64()

	log.Info("TX created", "tx", tx)

	err = writeBasicTxToDB(tx, evm.gateways.TXsCollection)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	return tx, nil
}

func (evm *EVMTxCreator) CreateTokenTransferTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey, scAddress string) (l1common.BasicTx, error) {

	fromAddress := crypto.PubkeyToAddress(pubKeyK)
	currentNonce, err := evm.getPendingNonceFor(fromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	gasprices, err := GetFeesDB()
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	gasPrice := getField(&gasprices, tx.BlockchainId)

	eth := EthereumLikeChainsFee{ApiUrl, ApiKey}
	fee := eth.GetCalculatedGasFee(new(big.Int).SetUint64(evm.gasLimit), gasPrice.FastFee)

	balance, err := evm.getBalanceFor(fromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	if balance.Cmp(fee) < 0 {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, fmt.Errorf("the balance of the account is not sufficient to cover ETH gas fee: the current balance is %v, the request value to transfer is %v", balance, fee))
	}

	contractAddress := common.HexToAddress(scAddress)
	decimals, err := evm.getTokenDecimal(contractAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	ethValue := big.NewInt(0)
	amount := new(big.Int)
	amount.SetString(tx.Value, 10)
	fullAmount := new(big.Int).Mul(amount, big.NewInt(int64(math.Pow10(int(decimals)))))

	data := evm.erc20TransferCallData(tx.ToAddress, fullAmount)
	erc20tx := types.NewTransaction(currentNonce, contractAddress, ethValue, evm.gasLimit, evm.gasPrice, data)

	signereth := types.NewEIP155Signer(evm.ChianID)
	h := signereth.Hash(erc20tx)

	fullTxJSON, err := json.Marshal(erc20tx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	tx.FullTx = string(fullTxJSON)
	tx.TxHash = h.Hex()
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: h.Hex(), InputIndex: 0}}
	tx.Status = l1common.TxCreated
	tx.Fee, _ = convertToMajorValue(fee).Float64()

	err = writeBasicTxToDB(tx, evm.gateways.TXsCollection)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	return tx, nil
}

// tx l1common.BasicTx, pubKeyK ecdsa.PublicKey, scAddress string
func (evm *EVMTxCreator) CreateTokenApproveTx(toAddress common.Address,
	amount float64,
	contractAddress common.Address) (error, []byte, common.Address, uint64, *big.Int) {

	decimals, err := evm.getTokenDecimal(contractAddress)
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.TxBuildError, err), nil, contractAddress, 0, big.NewInt(0)
	}

	//bigAmount := ethTransaction.FloatToBigInt(amount, int(decimals))
	bigFloatAmount := new(big.Float).SetFloat64(amount)
	bigAmount, _ := new(big.Float).Mul(bigFloatAmount, big.NewFloat(math.Pow10(int(decimals)))).Int(nil)

	callData := evm.erc20ApproveCallData(toAddress, bigAmount)

	gasLimit := uint64(4 * 21000)

	return nil, callData, contractAddress, gasLimit, big.NewInt(0)
}

func (evm *EVMTxCreator) Create1inchSwapTx(tx l1common.BasicTx,
	pubKeyK ecdsa.PublicKey,
	tokenIn evm_erc20.TokenDescription,
	tokenOut evm_erc20.TokenDescription) (l1common.BasicTx, error) {

	fromAddress := crypto.PubkeyToAddress(pubKeyK)

	amountIn, err := strconv.ParseFloat(tx.Value, 64)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	decimals, err := evm.getTokenDecimal(common.HexToAddress(tokenIn.Address))
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}
	bigFloatAmount := new(big.Float).SetFloat64(amountIn)
	bigAmount, _ := new(big.Float).Mul(bigFloatAmount, big.NewFloat(math.Pow10(int(decimals)))).Int(nil)

	slippage := int64(1)
	resp, err := oneinch.DoSwapRequest(evm.ChianID.Int64(), tokenIn.Address, tokenOut.Address, *bigAmount, fromAddress.String(), slippage)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}

	gasPrise, _ := new(big.Int).SetString(resp.GasPrice, 10)
	value, _ := new(big.Int).SetString(resp.Value, 10)
	from := common.HexToAddress(resp.From)
	toAddress := common.HexToAddress(resp.To)

	err, approveCallData, approveContractAddress, approveGasLimit, approveEthAmount := evm.CreateTokenApproveTx(toAddress, amountIn, common.HexToAddress(tokenIn.Address))
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	var txApprove l1common.BasicTx

	txApprove, err = evm.CreateEthereumTransaction(txApprove, from, approveContractAddress, approveEthAmount, approveGasLimit, evm.gasPrice, approveCallData)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	tx, err = evm.CreateEthereumTransaction(tx, from, toAddress, value, uint64(resp.Gas), gasPrise, []byte(resp.Data))

	tx.ApproveFullTx = txApprove.FullTx

	txApprove.Inputs[0].InputIndex = 1
	tx.Inputs = append(tx.Inputs, txApprove.Inputs[0])

	return tx, err
}

func (evm *EVMTxCreator) CreateUniSwapTx(tx l1common.BasicTx,
	pubKeyK ecdsa.PublicKey,
	tokenIn evm_erc20.TokenDescription,
	tokenOut evm_erc20.TokenDescription) (l1common.BasicTx, error) {

	fromAddress := crypto.PubkeyToAddress(pubKeyK)
	ethValue := big.NewInt(0)

	amountIn, err := strconv.ParseFloat(tx.Value, 64)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}
	// probably need to expose uniswap fee, that is hardcoded to 100, as a member to BasicTx?
	contractAddress, callData, err := uni.ExactInputSingleRouterV1(evm.gateways.Client, fromAddress, 100, tokenIn, amountIn, tokenOut)

	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	err, approveCallData, approveContractAddress, approveGasLimit, approveEthAmount := evm.CreateTokenApproveTx(contractAddress, amountIn, common.HexToAddress(tokenIn.Address))
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	var txApprove l1common.BasicTx

	txApprove, err = evm.CreateEthereumTransaction(txApprove, fromAddress, approveContractAddress, approveEthAmount, approveGasLimit, evm.gasPrice, approveCallData)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	tx, err = evm.CreateEthereumTransaction(tx, fromAddress, contractAddress, ethValue, evm.gasLimit, evm.gasPrice, callData)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	tx.ApproveFullTx = txApprove.FullTx

	txApprove.Inputs[0].InputIndex = 1
	tx.Inputs = append(tx.Inputs, txApprove.Inputs[0])

	return tx, err
}

func (evm *EVMTxCreator) CreateEthereumTransaction(tx l1common.BasicTx,
	fromAddress common.Address,
	contractAddress common.Address,
	ethValue *big.Int,
	gasLimit uint64,
	gasPrice *big.Int,
	callData []byte) (l1common.BasicTx, error) {

	currentNonce, err := evm.getPendingNonceFor(fromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	eth := EthereumLikeChainsFee{ApiUrl, ApiKey}
	fee := eth.GetCalculatedGasFee(new(big.Int).SetUint64(gasLimit), gasPrice)

	balance, err := evm.getBalanceFor(fromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	if balance.Cmp(fee) < 0 {
		return tx, errors.BuildAndLogErrorMsg(errors.ClientError, fmt.Errorf("the balance of the account is not sufficient to cover ETH gas fee: the current balance is %v, the request value to transfer is %v", balance, fee))
	}

	contractTx := types.NewTransaction(currentNonce, contractAddress, ethValue, evm.gasLimit, evm.gasPrice, callData)

	signereth := types.NewEIP155Signer(evm.ChianID)
	h := signereth.Hash(contractTx)

	fullTxJSON, err := json.Marshal(contractTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	tx.FullTx = string(fullTxJSON)
	tx.TxHash = h.Hex()
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: h.Hex(), InputIndex: 0}}
	tx.Status = l1common.TxCreated
	tx.Fee, _ = convertToMajorValue(fee).Float64()

	err = writeBasicTxToDB(tx, evm.gateways.TXsCollection)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	return tx, nil
}

func (evm *EVMTxCreator) erc20TransferCallData(toAddressStr string, amount *big.Int) []byte {
	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]

	toAddress := common.HexToAddress(toAddressStr)
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	return data
}

func (evm *EVMTxCreator) erc20ApproveCallData(toAddress common.Address, amount *big.Int) []byte {
	approveFnSignature := []byte("approve(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(approveFnSignature)
	methodID := hash.Sum(nil)[:4]

	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	return data
}

func (evm *EVMTxCreator) getTokenDecimal(contractAddress common.Address) (uint8, error) {
	return evm_erc20.GetTokenDecimal(contractAddress, evm.gateways.Client)
}

func (evm *EVMTxCreator) calculateFee(address common.Address) (*big.Int, error) {
	gasPrice, err := evm.gateways.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}
	evm.gasPrice = gasPrice

	return new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(evm.gasLimit)), nil
}

func (evm *EVMTxCreator) getPendingNonceFor(fromAddress common.Address) (uint64, error) {
	nonce, err := evm.gateways.Client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nonce, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	lastUsedNonce, err := gateways.GetEtherumLastUsedNonce(gateways.DB.Ethereum, fromAddress.String(), nonce)
	if err != nil {
		return nonce, errors.BuildAndLogErrorMsg(errors.NonceCountError, err)
	}

	if len(lastUsedNonce.LastNonces) >= 1 && lastUsedNonce.LastNonces[len(lastUsedNonce.LastNonces)-1] >= nonce {
		nonce = lastUsedNonce.LastNonces[len(lastUsedNonce.LastNonces)-1] + 1
	}
	return nonce, nil
}

func (evm *EVMTxCreator) getBalanceFor(fromAddress common.Address) (*big.Int, error) {
	ethBalance, err := evm.gateways.Client.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		return new(big.Int).SetUint64(0), errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	return ethBalance, nil
}
