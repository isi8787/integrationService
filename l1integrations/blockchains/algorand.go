package blockchains

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"
	"fmt"
	"math"
	"strconv"

	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/transaction"
	"github.com/algorand/go-algorand-sdk/types"
	log "github.com/sirupsen/logrus"
	ubiquity "gitlab.com/Blockdaemon/ubiquity/ubiquity-go-client/v1/pkg/client"
)

// TODO: Currently pointing to sandbox running on VM
var algodAddress = l1common.L1Configurations.Algorand.Uri
var algodToken = l1common.L1Configurations.Algorand.Token

// txidPrefix is prepended to a transaction when computing its txid
var txidPrefix = []byte("TX")

// GetALGOBalance retrieves algorand balance for an address
func GetALGOBalance(pk []byte) (l1common.AccountData, error) {
	var result l1common.AccountData
	var a types.Address

	n := copy(a[:], pk)
	if n != ed25519.PublicKeySize {
		return result, fmt.Errorf("generated public key has the wrong size, expected %d, got %d", ed25519.PublicKeySize, n)
	}

	result.Address = a.String()

	algodClient, err := algod.MakeClient(algodAddress, algodToken)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	accountInfo, err := algodClient.AccountInformation(result.Address).Do(context.Background())
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.BalanceError, err)
	}
	log.Info("Algorand info:", accountInfo)

	// TODO: Need to run against mainnet test
	result.Balance = fmt.Sprintf("%v", float64(accountInfo.Amount)/float64(1000000))
	log.Info("Algorand Balance:", result.Balance)
	log.Info("Algorand Balance:", accountInfo.Amount)
	return result, nil
}

// Blockdaemon support function for algorand, only valid for mainnet
func GetAlgoBalance(apiClient *ubiquity.APIClient, address, platform string) (float64, error) {
	//Blockdaemon support functions
	accessToken := gateways.GetAccessToken()
	// Context and platform
	ctx := context.WithValue(context.Background(), ubiquity.ContextAccessToken, accessToken)

	// Getting a balances for given address
	balances, resp, err := apiClient.AccountsAPI.GetListOfBalancesByAddress(ctx, platform, "p", address).Execute()

	respStatus, _ := strconv.ParseInt(resp.Status, 10, 64) // if we need t pass redirect statuses just incrase 299 to 399
	if err != nil || respStatus < 200 || respStatus > 299 {
		return 0, errors.BuildAndLogErrorMsgWithData(errors.BalanceError, err, *resp)
	}

	balance := balances[0]
	confirmedBalance, err := strconv.Atoi(balance.GetConfirmedBalance())
	if err != nil {
		return 0, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}
	currency := balance.GetCurrency()
	//format value into BTC unit
	return float64(confirmedBalance) / math.Pow10(int(*currency.NativeCurrency.Decimals)), nil
}

func GetAlgoTxFee() uint64 {
	return uint64(transaction.MinTxnFee)
}

// ALGOTx prepare transaction for sending ALGO from one address to another
// stores the transaction in internal DB until custody service generates signature
func ALGOTx(tx l1common.BasicTx, pk []byte) (l1common.BasicTx, error) {
	var result l1common.BasicTx

	//Format publicKey into algorand format
	var a types.Address
	n := copy(a[:], pk)
	if n != ed25519.PublicKeySize {
		return result, fmt.Errorf("generated public key has the wrong size, expected %d, got %d", ed25519.PublicKeySize, n)
	}

	fromAddress := a.String()
	tx.FromAddress = fromAddress

	//Initialize client for communicating with algorand node
	algodClient, err := algod.MakeClient(algodAddress, algodToken)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	// Construct the transaction
	// Get the suggested transaction parameters
	txParams, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	fromAddr := fromAddress
	toAddr := tx.ToAddress

	value, err := strconv.ParseFloat(tx.Value, 64)
	var amount uint64 = uint64(1000000 * value)
	var minFee uint64 = transaction.MinTxnFee
	tx.Fee = float64(minFee) / float64(1000000)
	var note []byte
	genID := txParams.GenesisID
	genHash := txParams.GenesisHash
	firstValidRound := uint64(txParams.FirstRoundValid)
	lastValidRound := uint64(txParams.LastRoundValid)
	newtx, err := transaction.MakePaymentTxnWithFlatFee(fromAddr, toAddr, minFee, amount, firstValidRound, lastValidRound, note, "", genID, genHash)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.CreateTxError, err)
	}
	unsignedTx := types.SignedTxn{
		Txn: newtx,
	}

	// Prepare ALGO TX hash to be signed
	encodedTx := msgpack.Encode(unsignedTx.Txn)
	// Prepend the hashable prefix
	msgParts := [][]byte{txidPrefix, encodedTx}
	hashBytes := bytes.Join(msgParts, nil)
	hexHash := hex.EncodeToString(hashBytes)

	txJSON, err := json.Marshal(unsignedTx)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	tx.TxHash = hexHash
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: hexHash, InputIndex: 0}}
	tx.FullTx = string(txJSON)
	tx.Status = l1common.TxCreated

	err = gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil

}

// CompleteALGOTx appends signature and submits transaction to algorand node
func CompleteALGOTx(tx l1common.BasicTx, signature string) (string, error) {
	var result string

	var unsignedTx types.SignedTxn
	err := json.Unmarshal([]byte(tx.FullTx), &unsignedTx)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	algodClient, err := algod.MakeClient(algodAddress, algodToken)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	fullsig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.Base64DecodeError, err)
	}

	//Convert signature into algorand go-sdk format
	var s types.Signature
	n := copy(s[:], fullsig)
	if n != len(s) {
		return result, errors.BuildAndLogErrorMsg(errors.SignatureError, err)
	}

	// Construct the SignedTxn
	signedTxn := types.SignedTxn{
		Sig: s,
		Txn: unsignedTx.Txn,
	}

	stxBytes := msgpack.Encode(signedTxn)

	// Submit the signed transaction
	sendResponse, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}

	log.Info("Submitted transaction: ", sendResponse)
	txID := crypto.GetTxID(signedTxn.Txn)

	// Wait for confirmation
	// TODO: It is need for all blockchains.
	// Wait for tx confirmation in separate goroutine and update tx state in tx collection when it respond.
	go func() error {
		confirmedTxn, err := future.WaitForConfirmation(algodClient, txID, 4, context.Background())
		if err != nil {
			return errors.BuildAndLogErrorMsg(errors.ConfirmTxError, err)
		}
		log.Info(fmt.Sprintf("Confirmed Transaction: %s in Round %d\n", txID, confirmedTxn.ConfirmedRound))
		return nil
	}()

	signedTxJSON, err := json.Marshal(signedTxn)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	tx.FullTx = string(signedTxJSON)
	tx.Inputs[0].Signature = signature
	tx.Status = l1common.TxSubmitted
	err = gateways.UpdateTx(tx.TxHash, tx, gateways.DB.Transactions)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return txID, nil
}
