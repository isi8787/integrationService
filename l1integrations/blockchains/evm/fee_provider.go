package evm

import (
	"context"
	"encoding/json"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
)

var infuraURI string = l1common.L1Configurations.Infura.Goerli
var fujiCChainURI string = l1common.L1Configurations.Infura.Fuji
var ApiUrl string = l1common.L1Configurations.Ethereum.EtherscanURLGasOracle
var ApiKey string = l1common.L1Configurations.Ethereum.EtherscanAPIKEY
var BscScanUrl string = l1common.L1Configurations.BSC.BscScanUrl
var BscScanApiKey string = l1common.L1Configurations.BSC.BscScanApiKey
var PolygonScanUrl string = l1common.L1Configurations.Polygon.PolygonScanUrl
var PolygonScanApiKey string = l1common.L1Configurations.Polygon.PolygonScanApiKey

type ETHLikeChainsGasOracleAPIHeader struct {
	Status  string                    `json:"status"`
	Message string                    `json:"message"`
	Result  ETHLikeChainsGasOracleAPI `json:"result"`
}

type ETHLikeChainsGasOracleAPI struct {
	SafeGasPrice    string `json:"SafeGasPrice"`
	ProposeGasPrice string `json:"ProposeGasPrice"`
	FastGasPrice    string `json:"FastGasPrice"`
}

type ETHLikeChainsGasOracleFees struct {
	SafeGasPrice    *big.Int `json:"SafeGasPrice"`
	ProposeGasPrice *big.Int `json:"ProposeGasPrice"`
	FastGasPrice    *big.Int `json:"FastGasPrice"`
}

type EthereumLikeChainsFee struct {
	ApiUrl string
	ApiKey string
}

// ! this is temporary ! need API
func GetAvaxTxFee() *big.Int {
	client, err := ethclient.Dial(fujiCChainURI)
	if err != nil {
		log.Error(err.Error())
		return nil
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Error(err.Error())
		return nil
	}

	return gasPrice
}

// Getting min eth from ete
func (epf *EthereumLikeChainsFee) GetMinEthGasLimit() *big.Int {
	return new(big.Int).SetUint64(80433)
}

// Getting basic safe gas fee
func (epf *EthereumLikeChainsFee) GetBasicSafeGasFee() *big.Int {
	gasPrice, err := epf.GetSafeGasPrice()
	if err != nil {
		return nil
	}
	gasFee := epf.GetCalculatedGasFee(epf.GetBasicTxGasLimit(), gasPrice)
	return gasFee.Mul(gasFee, gasPrice)
}

// Getting basic propose gas fee
func (epf *EthereumLikeChainsFee) GetBasicProposeGasFee() *big.Int {
	gasPrice, err := epf.GetProposeGasPrice()
	if err != nil {
		return nil
	}
	gasFee := epf.GetCalculatedGasFee(epf.GetBasicTxGasLimit(), gasPrice)
	return gasFee.Mul(gasFee, gasPrice)
}

// Getting basic fast gas fee
func (epf *EthereumLikeChainsFee) GetBasicFastGasFee() *big.Int {
	gasPrice, err := epf.GetFastGasPrice()
	if err != nil {
		return nil
	}
	gasFee := epf.GetCalculatedGasFee(epf.GetBasicTxGasLimit(), gasPrice)
	return gasFee.Mul(gasFee, gasPrice)
}

// Getting pure tx gas limit
func (epf *EthereumLikeChainsFee) GetBasicTxGasLimit() *big.Int {
	return new(big.Int).SetUint64(21000)
}

// Getting ERC20 tx gas limit
func (epf *EthereumLikeChainsFee) GetERC20GasLimit() *big.Int {
	return new(big.Int).SetUint64(2204*68 + 21000)
}

// Getting UniSwap tx gas limit
func (epf *EthereumLikeChainsFee) GetUniSwapGasLimit() *big.Int {
	return new(big.Int).SetUint64(200000)
}

// GetSafeGasFee Estimates safe gas fee
func (epf *EthereumLikeChainsFee) GetSafeGasPrice() (*big.Int, error) {
	gasPrice, err := epf.GetGasOracle()
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	return gasPrice.SafeGasPrice, nil
}

// GetProposeGasFee Estimates propose gas fee
func (epf *EthereumLikeChainsFee) GetProposeGasPrice() (*big.Int, error) {
	gasPrice, err := epf.GetGasOracle()
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	return gasPrice.ProposeGasPrice, nil
}

// GetFastGasFee Estimates fast gas fee
func (epf *EthereumLikeChainsFee) GetFastGasPrice() (*big.Int, error) {
	gasPrice, err := epf.GetGasOracle()
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	extraFast := new(big.Int).Mul(gasPrice.FastGasPrice, big.NewInt(3))
	return extraFast, nil
}

// Getting gas oracle
func (epf *EthereumLikeChainsFee) GetGasOracle() (ETHLikeChainsGasOracleFees, error) {
	URL := epf.ApiUrl + epf.ApiKey
	resp, err := http.Get(URL)
	gasOracle := ETHLikeChainsGasOracleAPIHeader{}
	if err != nil {
		return ETHLikeChainsGasOracleFees{}, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ETHLikeChainsGasOracleFees{}, errors.BuildAndLogErrorMsg(errors.DecodeBodyError, err)
	}
	if resp.StatusCode > 299 {
		return ETHLikeChainsGasOracleFees{}, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}
	defer resp.Body.Close()
	errJson := json.Unmarshal(body, &gasOracle)
	if errJson != nil {
		return ETHLikeChainsGasOracleFees{}, errors.BuildAndLogErrorMsg(errors.UnmarshallError, errJson)
	}

	safeGas, ok := new(big.Float).SetString(gasOracle.Result.SafeGasPrice)
	if !ok {
		log.Error("Error making big.Int")
	}
	proposeFee, ok := new(big.Float).SetString(gasOracle.Result.ProposeGasPrice)
	if !ok {
		log.Error("Error making big.Int")
	}
	fastFee, ok := new(big.Float).SetString(gasOracle.Result.FastGasPrice)
	if !ok {
		log.Error("Error making big.Int")
	}

	safe := new(big.Int)
	safe, _ = safeGas.Int(safe)

	proposed := new(big.Int)
	proposed, _ = proposeFee.Int(proposed)

	fast := new(big.Int)
	fast, _ = fastFee.Int(fast)
	fast.Mul(fast, big.NewInt(4))

	return ETHLikeChainsGasOracleFees{safe, proposed, fast}, errJson
}

// Convert  gwei to wei
func GweiToWei(gwei *big.Int) *big.Int {
	value := big.NewInt(1000000000)
	gwei.Mul(gwei, value)
	return gwei
}

// Getting calculated gas fee in wei
func (epf *EthereumLikeChainsFee) GetCalculatedGasFee(gasLimit *big.Int, gasPrice *big.Int) *big.Int {
	return gasLimit.Mul(gasLimit, gasPrice)
}
