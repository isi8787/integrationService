package blockchains

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"

	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
	ubiquity "gitlab.com/Blockdaemon/ubiquity/ubiquity-go-client/v1/pkg/client"
	ubiquityTx "gitlab.com/Blockdaemon/ubiquity/ubiquity-go-client/v1/pkg/tx"

	ecdsasecp "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var bitcoinNetwork = setNetwork()

// When we creating BTC tx differance between inputs and outputs is the constant 1000 it is the fee of tx.
func GetBTCFee() uint64 {
	return 1000
}

func setNetwork() *chaincfg.Params {
	var chainId string = l1common.L1Configurations.Bitcoin.ChainId
	var network *chaincfg.Params
	if chainId == "testnet" {
		network = &chaincfg.TestNet3Params
	} else {
		network = &chaincfg.MainNetParams
	}
	return network
}

func getBTCAddressFromECDSA(pk ecdsa.PublicKey) (string, error) {
	compressedBytes := SerializeUncompressed(&pk)
	addresspubkey, _ := btcutil.NewAddressPubKey(compressedBytes, bitcoinNetwork)
	sourceAddress, err := btcutil.DecodeAddress(addresspubkey.EncodeAddress(), bitcoinNetwork)
	if err != nil {
		return "", errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}
	return sourceAddress.EncodeAddress(), nil
}

// GetBTCBalances support function to retrieve balances associated with
// a BTC address
func GetBTCBalances(senderPubKey ecdsa.PublicKey) (l1common.AccountData, error) {
	var result l1common.AccountData

	address, err := getBTCAddressFromECDSA(senderPubKey)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}
	result.Address = address

	//Call supporting blockdaemon wrapper function
	balance, err := GetBTCBalance(gateways.BD, result.Address)
	if err != nil {
		return result, err
	}
	result.Balance = fmt.Sprintf("%f", balance)

	return result, nil
}

// CreateBTCTx creates the initial bitcoin transaction and corresponding inputs that require signature
// TODO: need destination address validation function
func CreateBTCTx(senderPubKey ecdsa.PublicKey, destination string, amount float64, apiClient *ubiquity.APIClient) (*wire.MsgTx, []l1common.TxInputs, string, float64, error) {
	if amount <= 0 {
		return nil, nil, "", 0, fmt.Errorf("transfer amount must be larger than 0")
	}

	if apiClient == nil {
		return nil, nil, "", 0, fmt.Errorf("Error creating blockdaemon client")
	}

	//TODO: add public key validation function

	var inputList []l1common.TxInputs
	//get balances for doing initial check and accounting around transaction
	btcAccount, err := GetBTCBalances(senderPubKey)
	if err != nil {
		return nil, nil, "", 0, fmt.Errorf("failed to get balance: ", err)
	}

	intBalance, err := strconv.ParseFloat(btcAccount.Balance, 64)
	if err != nil {
		return nil, nil, "", 0, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	// checking for sufficiency of account
	if intBalance < amount {
		return nil, inputList, "", 0, fmt.Errorf("the balance of the account is not sufficient: the current balance is %v, the request value to transfer is %v", intBalance, amount)
	} else if intBalance < amount+(1000/math.Pow10(8)) {
		amount = intBalance - (1000 / math.Pow10(8))
		//return nil, inputList, "", fmt.Errorf("the balance of the account is not sufficient to cover transaction fee: the current balance is %v, the request value to transfer is %v", intBalance, amount)
	}

	// TODO: need to get fee for transaction
	//TODO: also need to allow user to set fee to change processing speed
	//feeresp, _, err := apiClient.TransactionsAPI.FeeEstimate(ctx, platform, "testnet").Execute()
	//if err != nil {
	//	panic(fmt.Errorf("failed to get a fee: ", err))
	//}

	//fee := fmt.Sprintf("%v", feeresp.GetEstimatedFees().Medium)
	//int_fee, err := strconv.Atoi(fee)
	//if err != nil {
	//	panic(fmt.Errorf("failed to retrive fee: ", err))
	//}

	//get the list of UTXOs for sender address
	txs, err := getUTXO(btcAccount.Address)
	if err != nil {
		return nil, inputList, "", 0, err
	}
	var btcTx ubiquityTx.BitcoinTransaction

	//convert value into integer64 given 8 decimals for btc
	amountF := amount * math.Pow10(8)
	var aggregatedValue int64
	btcTx.Network = l1common.L1Configurations.Bitcoin.ChainId

	//Loop over UTXOs to prepare BTC Tx inputs and outputs
	// using blockdaemon structure
	//TODO: need additional optimization to organized the UTXO into best possible order given transfer value
	spentUTXOs, err := gateways.GetBitcoinUsedUtxos(gateways.DB.Bitcoin, btcAccount.Address)
	if err != nil {
		return nil, nil, "", 0, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	complete := false
	for _, val := range txs.Data {
		if !val.IsSpent && !spentUTXOs[val.Mined.TxId] {
			if val.Value > int64(amountF+1000) {
				aggregatedValue = aggregatedValue + val.Value
				btcTx.From = append(btcTx.From, ubiquityTx.TxInput{Source: val.Mined.TxId, Index: uint32(val.Mined.Index)})
				changeAmount := aggregatedValue - int64(amountF)
				destinationAmount := val.Value - changeAmount
				tmp := []ubiquityTx.TxOutput{
					{Destination: destination, Amount: destinationAmount},
					{Destination: btcAccount.Address, Amount: (changeAmount - int64(1000))},
				}
				btcTx.To = append(btcTx.To, tmp...)
				complete = true
				break
			} else {
				aggregatedValue = aggregatedValue + val.Value
				btcTx.From = append(btcTx.From, ubiquityTx.TxInput{Source: val.Mined.TxId, Index: uint32(val.Mined.Index)})
				if aggregatedValue > int64(amountF+1000) {
					changeAmount := aggregatedValue - int64(amountF)
					destinationAmount := val.Value - changeAmount
					tmp := []ubiquityTx.TxOutput{
						{Destination: destination, Amount: destinationAmount},
						{Destination: btcAccount.Address, Amount: (changeAmount - int64(1000))},
					}
					btcTx.To = append(btcTx.To, tmp...)
					complete = true
					break
				}
			}
		} else {
			log.Info("UTXOS is spent or in the process of being spent")
		}
	}

	if !complete {
		log.Error("Not enough UTXOS, retry later")
		return nil, nil, "", 0, fmt.Errorf("Bitcoin Transaction needs to retried later not enough UTXOs avaialble")
	}

	//simple validation
	if err := BTCvalidate(btcTx); err != nil {
		return nil, inputList, "", 0, fmt.Errorf("Bitcoin Transaction validation failure: %v", err)
	}

	//Convert blockdaemon structure to wire.MsgTx for
	// better support in generating hashes and signatures
	msgTx := wire.NewMsgTx(wire.TxVersion)

	//UTXO outputs
	for _, out := range btcTx.To {
		destAddr, err := btcutil.DecodeAddress(out.Destination, bitcoinNetwork)
		if err != nil {
			return nil, inputList, "", 0, fmt.Errorf("failed to decode destination address: %v", err)
		}
		pkScript, err := txscript.PayToAddrScript(destAddr)
		if err != nil {
			return nil, inputList, "", 0, fmt.Errorf("failed to build P2PKH script: %v", err)
		}
		log.Info("pkScript", pkScript, string(pkScript), hex.EncodeToString(pkScript))

		msgTx.AddTxOut(wire.NewTxOut(out.Amount, pkScript))
	}

	//UTXO inputs
	for _, in := range btcTx.From {
		txHash, err := chainhash.NewHashFromStr(in.Source)
		if err != nil {
			return nil, inputList, "", 0, fmt.Errorf("failed to get hash from source string: %v", err)
		}
		log.Info("txHash", txHash, string(txHash[:]), hex.EncodeToString(txHash[:]))

		msgTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(txHash, in.Index), nil, nil))
	}

	//Loop over inputs to generate hashes
	for i, _ := range msgTx.TxIn {
		pubKeyAddress, err := btcutil.DecodeAddress(btcAccount.Address, bitcoinNetwork)
		if err != nil {
			return nil, inputList, "", 0, fmt.Errorf("failed to decode address: %v", err)
		}

		inputPKScript, err := txscript.PayToAddrScript(pubKeyAddress)
		if err != nil {
			return nil, inputList, "", 0, fmt.Errorf("failed to build P2PKH script: %v", err)
		}

		//Calculate the input hash that requires signature
		hash, err := txscript.CalcSignatureHash(inputPKScript, txscript.SigHashAll, msgTx, i)
		if err != nil {
			return nil, inputList, "", 0, err
		}

		hexHash := hex.EncodeToString(hash)
		tmp := l1common.TxInputs{Hash: hexHash, InputIndex: i, Signature: ""}
		log.Info("UTXO Input Hash", hexHash)
		inputList = append(inputList, tmp)

	}

	return msgTx, inputList, btcAccount.Address, amount, nil
}

// getUTXO is a manual support apis from blockdaemon to get the UTXO from a user address
// TODO: need additional optimization to organized the UTXO into best possible order given transfer value
func getUTXO(address string) (l1common.UTXOResponse, error) {
	var response l1common.UTXOResponse
	bitcoinUri := l1common.L1Configurations.Blockdaemon.Bitcoin.Uri
	url := bitcoinUri + "account/" + address + "/utxo"
	method := "GET"

	//TODO: need to migrate to https
	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return response, err
	}
	blockdaemonToken := l1common.L1Configurations.Blockdaemon.AccessToken
	req.Header.Add("Authorization", "Bearer "+blockdaemonToken)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return response, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return response, err
	}

	err = json.Unmarshal([]byte(string(body)), &response)
	if err != nil {
		fmt.Println(err)
		return response, err
	}

	return response, nil
}

// Struct validation wasn't used in order to eliminate extra dependencies for SDK users.
func BTCvalidate(t ubiquityTx.BitcoinTransaction) error {
	if strings.TrimSpace(t.Network) == "" {
		return fmt.Errorf("field 'Network' is required")
	}
	if len(t.From) == 0 {
		return fmt.Errorf("field 'From' must not be empty")
	}
	for _, in := range t.From {
		if in.Source == "" {
			return fmt.Errorf("input fields 'Source' and 'Index' must be set")
		}
	}
	if len(t.To) == 0 {
		return fmt.Errorf("field 'To' must not be empty")
	}
	for _, out := range t.To {
		if out.Destination == "" {
			return fmt.Errorf("output fields 'Destination' and 'Amount' must be set")
		}
	}

	return nil
}

// GetBTCBalance retrieve bitcoin balance for an address
func GetBTCBalance(apiClient *ubiquity.APIClient, address string) (float64, error) {
	//Blockdaemon support functions
	accessToken := gateways.GetAccessToken()
	// Context and platform
	ctx := context.WithValue(context.Background(), ubiquity.ContextAccessToken, accessToken)

	var platform string
	if platform = os.Getenv("UBI_PLATFORM"); platform == "" {
		platform = "bitcoin"
	}

	// Getting a balances for given address
	balances, resp, err := apiClient.AccountsAPI.GetListOfBalancesByAddress(ctx, platform, "testnet", address).Execute()
	//TODO: for resp we should check the status to handle errors more exactly
	if err != nil {
		return 0, fmt.Errorf("failed to get a balances for given address %s, status: '%s' and error '%v'", address, resp.Status, err)
	}
	balance := balances[0]
	confirmedBalance, err := strconv.Atoi(balance.GetConfirmedBalance())
	if err != nil {
		return 0, err
	}
	currency := balance.GetCurrency()
	//format value into BTC unit
	return float64(confirmedBalance) / math.Pow10(int(*currency.NativeCurrency.Decimals)), nil
}

// SendBTCModified sends BTC transaction. Under the hood it uses Ubiquity TxSend API.
// It internally calls the signBitcoinTx function to prepare final format of transaction
// with all supporting signatures added
func SendBTCModified(messageHash string, inputs []l1common.TxInputs, pubKeyK ecdsa.PublicKey, apiClient *ubiquity.APIClient) (string, error) {
	var result string
	accessToken := gateways.GetAccessToken()
	// Context and platform
	ctx := context.WithValue(context.Background(), ubiquity.ContextAccessToken, accessToken)

	tx, err := gateways.ReadTx(messageHash, gateways.DB.Transactions)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ReadTxError, err)
	}

	//Retrieve store tranaction from DB
	var msgTx wire.MsgTx
	err = json.Unmarshal([]byte(tx.FullTx), &msgTx)

	//Prepare signed transactions
	signedTx, err := signBitcoinTx(inputs, &msgTx, bitcoinNetwork, pubKeyK)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.SignatureError, err)
	}

	txReceipt, _, err := apiClient.TransactionsAPI.TxSend(ctx, "bitcoin", "testnet").
		SignedTx(ubiquity.SignedTx{Tx: signedTx}).Execute()

	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}
	result = txReceipt.Id

	tx.Status = l1common.TxSubmitted
	err = gateways.UpdateTx(tx.TxHash, tx, gateways.DB.Transactions)

	return result, err
}

// signBitcoinTx will add the externally generated signatures for each BTC input
// into the corresponding wire.MsgTx in correct location and return the hex encoded tx
func signBitcoinTx(inputs []l1common.TxInputs, transaction *wire.MsgTx, netParams *chaincfg.Params, pubKeyK ecdsa.PublicKey) (string, error) {
	//public key bytes
	publicKeyBytes := SerializeUncompressed(&pubKeyK)

	//loop over inputs, decode signature and append signature to BTC transaction
	for _, input := range inputs {
		// variables to convert from V,S,R signature to byte slices
		var s secp256k1.ModNScalar
		var r secp256k1.ModNScalar
		var sBytes [32]byte
		var rBytes [32]byte

		var fullSignature l1common.EcdsaSignature
		err := json.Unmarshal([]byte(input.Signature), &fullSignature)
		if err != nil {
			return "", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
		}

		sigSBytes := fullSignature.S.Bytes()
		for i, val := range sigSBytes {
			sBytes[i] = val
		}

		sigRBytes := fullSignature.R.Bytes()
		for i, val := range sigRBytes {
			rBytes[i] = val
		}

		s.SetBytes(&sBytes)
		r.SetBytes(&rBytes)
		// TODO check if V is needed or set internally by ecdsasecp.NewSignature
		//format signature into final format
		signatureParsed := ecdsasecp.NewSignature(&r, &s)
		completeSig := append(signatureParsed.Serialize(), byte(txscript.SigHashAll))

		//generate signature script
		signed, _ := SignatureScript(completeSig, publicKeyBytes)

		//Add signature for each inpute
		transaction.TxIn[input.InputIndex].SignatureScript = signed

	}

	var signedTx bytes.Buffer
	transaction.Serialize(&signedTx)

	hexSignedTx := hex.EncodeToString(signedTx.Bytes())

	return hexSignedTx, nil
}

// SignatureScript prepares bitcoin script from signature and publicKeyBytes
func SignatureScript(sigbytes []byte, publicKeyBytes []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().AddData(sigbytes).AddData(publicKeyBytes).Script()
}

// BTCTxvalidate minimal validation of BTC transaction
// according to golang btcd specs to check for errors
func BTCTxvalidate(t ubiquityTx.BitcoinTransaction) error {
	if strings.TrimSpace(t.Network) == "" {
		return fmt.Errorf("field 'Network' is required")
	}
	if len(t.From) == 0 {
		return fmt.Errorf("field 'From' must not be empty")
	}
	for _, in := range t.From {
		if in.Source == "" {
			return fmt.Errorf("input fields 'Source' and 'Index' must be set")
		}
	}
	if len(t.To) == 0 {
		return fmt.Errorf("field 'To' must not be empty")
	}
	for _, out := range t.To {
		if out.Destination == "" {
			return fmt.Errorf("output fields 'Destination' and 'Amount' must be set")
		}
	}

	return nil
}

// BTCTx prepare transaction for sending BTC by taking common data structure BasicTx
// and preparing btc transaction
// TODO: need to track UTXOs for transactions that are pending to avoid doble spending
// TODO: need to create event listener after transaction is commited to blockchain to detect completion
func BTCTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	// retrive value being sent for btc
	amount, err := strconv.ParseFloat(tx.Value, 32)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	//prepare btc transaction
	btcTx, inputList, address, finalAmount, err := CreateBTCTx(pubKeyK, tx.ToAddress, amount, gateways.BD)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	//update BasicTx data and store in DB
	fullTxJSON, err := json.Marshal(btcTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsgWithData(errors.TxEncoding, err, btcTx)
	}
	tx.FullTx = string(fullTxJSON)
	tx.TxHash = inputList[0].Hash
	tx.Inputs = inputList
	tx.Status = l1common.TxCreated
	tx.FromAddress = address
	tx.Fee = float64(GetBTCFee()) / math.Pow10(8)
	tx.Amount = float64(finalAmount)

	fmt.Println("BTCTx(): .txFromAddrress: ", tx.FromAddress)

	err = gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil
}

//Support functions for bitcoin transactions

// SerializeUncompressed is used to convert ECDSA public key in
// X Y format to byte slice in right orderer
func SerializeUncompressed(p *ecdsa.PublicKey) []byte {
	b := make([]byte, 0, 65)
	b = append(b, l1common.PubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// paddedAppend support function to combine bytes slices
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
