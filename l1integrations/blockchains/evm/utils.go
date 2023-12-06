package evm

import (
	"encoding/json"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"
	"math/big"
	"reflect"
	"strconv"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"go.mongodb.org/mongo-driver/mongo"
)

type evmGateways struct {
	NodeURL         string
	NonceCollection *mongo.Collection
	TXsCollection   *mongo.Collection
	Client          *ethclient.Client
}

func NewEvmGateways(nodeUrl string, nonceCollection *mongo.Collection, txsCollection *mongo.Collection) (evmGateways, error) {
	eg := evmGateways{
		NodeURL:         nodeUrl,
		NonceCollection: nonceCollection,
		TXsCollection:   txsCollection,
	}
	client, err := ethclient.Dial(eg.NodeURL)
	if err != nil {
		return eg, err
	}
	eg.Client = client
	return eg, nil
}

func convertToMinorValue(value string) (*big.Int, error) {
	var intValue = new(big.Int)
	valueInEth, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return intValue, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	ethValue := big.NewFloat(valueInEth) // in wei (1 eth)
	ethTowei := big.NewFloat(1000000000000000000)

	var fvalue = new(big.Float)
	fvalue.Mul(ethValue, ethTowei)
	fvalue.Int(intValue)

	return intValue, nil
}

func convertToMajorValue(val *big.Int) *big.Float {
	num := big.NewFloat(0).SetInt(val)
	dem := big.NewFloat(0).SetInt(big.NewInt(params.Ether))
	return big.NewFloat(0).Quo(num, dem)
}

func marshalToJson(fullTx *types.Transaction) ([]byte, error) {
	fullTxJSON, err := json.Marshal(fullTx)
	if err != nil {
		return fullTxJSON, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	return fullTxJSON, nil
}

func unmarshalFromJson(serializedTx []byte) (types.Transaction, error) {
	var fullTx types.Transaction

	err := json.Unmarshal([]byte(serializedTx), &fullTx)
	if err != nil {
		return fullTx, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	return fullTx, nil
}

func writeBasicTxToDB(tx l1common.BasicTx, txCollection *mongo.Collection) error {
	err := gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}
	return nil
}

func readBasicTxFromDB(txHash string, txCollection *mongo.Collection) (l1common.BasicTx, error) {
	tx, err := gateways.ReadTx(txHash, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ReadTxError, err)
	}
	return tx, nil
}

func updateBasicTxInDB(txHash string, tx l1common.BasicTx, txsCollection *mongo.Collection) error {
	err := gateways.UpdateTx(txHash, tx, txsCollection)
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}
	return nil
}

func getField(v *l1common.ChainsFees, field string) l1common.GasFee {
	r := reflect.ValueOf(v)
	f := reflect.Indirect(r).FieldByName(field)
	return f.Interface().(l1common.GasFee)
}

// Cron job to get fees every 1 minutes
func GetFeesDB() (l1common.ChainsFees, error) {
	fees, err := gateways.JsonDataGet("unique_ID_gas_fees")
	if err != nil {
		return l1common.ChainsFees{}, err
	}

	var feesObj []l1common.ChainsFees
	err = json.Unmarshal([]byte(fees), &feesObj)
	if err != nil {
		return l1common.ChainsFees{}, err
	}

	return feesObj[0], nil
}
