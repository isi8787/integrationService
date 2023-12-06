package blockchains

import (
	"crypto/ecdsa"
	"encoding/json"
	"finco/l1integration/common"
	"finco/l1integration/errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	xrpd "github.com/rubblelabs/ripple/data"
)

// import (
// 	xrp "github.com/go-chain/go-xrp"
// )

type XRPPaymentTx struct {
	TransactionType string // tx type for example "Payment"
	Account         string // hash
	Destination     string // hash
	Amount          string
	Fee             string
	Flags           int64
	Sequence        uint32
}

type XRPComand struct {
	Id      int64  `json:"id"`
	Command string `json:"command"`
	TxBlob  string `json:"tx_blob"`
}

type XRPAccountData struct {
	Account           string `json:"Account"`
	Balance           string `json:"Balance"`
	Flags             int64  `json:"Flags"`
	LedgerEntryType   string `json:"LedgerEntryType"`
	OwnerCount        int64  `json:"OwnerCount"`
	PreviousTxnID     string `json:"PreviousTxnID"`
	PreviousTxnLgrSeq string `json:"PreviousTxnLgrSeq"`
	Sequence          uint32 `json:"Sequence"`
	Index             string `json:"index"`
}

type XRPXRPAPIResponseAcccountInfo struct {
	AccountData        XRPAccountData `json:"account_data"`
	LedgerCurrentIndex int64          `json:"ledger_current_index"`
	QueueData          interface{}
	Status             string `json:"status"`
	Validated          bool   `json:"validated"`
}

type XRPXRPAPIResponse struct {
	Result XRPXRPAPIResponseAcccountInfo `json:"result"` // TODO: need to change for common solution
}

type XRPAPIRequsetAcccountInfo struct {
	Account     string `json:"account"`
	Strinct     bool   `json:"strict"`
	LedgerIndex string `json:"ledger_index"`
	Queue       bool   `json:"queue"`
}

type XRPAPIRequset struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

func getXRPAccountInfo(account string) XRPXRPAPIResponseAcccountInfo {
	reqBody := XRPAPIRequset{
		Method: "account_info",
		Params: make([]interface{}, 1),
	}
	accInfoReqBody := XRPAPIRequsetAcccountInfo{
		Account:     account,
		Strinct:     true,
		LedgerIndex: "current",
		Queue:       true,
	}
	reqBody.Params[0] = accInfoReqBody

	serialized, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, XRPTestNetAPIURL, strings.NewReader(string(serialized)))

	client := &http.Client{}

	resp, _ := client.Do(req)
	data, _ := ioutil.ReadAll(resp.Body)
	var respXRP XRPXRPAPIResponse
	json.Unmarshal(data, &respXRP)

	return respXRP.Result
}

func createXRPPaymentTx(senderPubKey ecdsa.PublicKey, destination string, amount string) XRPPaymentTx {
	xrpTx := XRPPaymentTx{}

	xrpTx.TransactionType = "Payment"
	xrpTx.Account = senderPubKey.X.String() // TODO: Check is correct key format geting
	xrpTx.Destination = destination
	xrpTx.Amount = amount
	xrpTx.Fee = "0.00001" // fixed price
	xrpTx.Flags = 0

	accInfo := getXRPAccountInfo(xrpTx.Account)

	xrpTx.Sequence = accInfo.AccountData.Sequence

	return xrpTx
}

func createXRPPaymentTx_(account xrpd.Account, destination string, amount string) xrpd.Hash256 {
	accInfo := getXRPAccountInfo(account.String())
	flags := xrpd.TxPartialPayment
	am, _ := strconv.ParseFloat(amount, 64)
	value, _ := xrpd.NewNativeValue(int64(am * 1000000))
	txB := xrpd.TxBase{
		TransactionType: xrpd.PAYMENT,
		Flags:           &flags,
		Account:         account,
		Sequence:        accInfo.AccountData.Sequence,
		Fee:             *value,
		Hash:            xrpd.Hash256{},
	}
	amm, _ := xrpd.NewAmount(int64(am * 1000000))
	destAcc, _ := xrpd.NewAccountFromAddress(destination)
	pTx := xrpd.Payment{txB, *destAcc, *amm, nil, nil, nil, nil, nil, nil}

	pTx.InitialiseForSigning()
	copy(pTx.GetPublicKey().Bytes(), account.Bytes())
	pTx.GetHash()

	// hash, _, _ := xrpd.SigningHash(pTx)

	return xrpd.Hash256{}
}

func XRPTx(tx common.BasicTx, senderPubKey ecdsa.PublicKey) (common.BasicTx, error) {
	xrpTx := createXRPPaymentTx(senderPubKey, tx.ToAddress, tx.Value)

	fullTxJSON, err := json.Marshal(xrpTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsgWithData(errors.TxEncoding, err, xrpTx)
	}

	tx.FullTx = string(fullTxJSON)
	// TODO: Geneare local hash of tx for saving in DB
	// for completeTX input format can be {hash: "localyGeneratedHash", "signature": "txBlob value"}
	tx.TxHash = "hash"
	tx.Inputs = []common.TxInputs{}
	tx.Status = common.TxCreated
	tx.FromAddress = xrpTx.Account
	tx.Fee, _ = strconv.ParseFloat(xrpTx.Fee, 64)

	return tx, nil
}

// TestNetURL todo..
const (
	XRPTestNetURL = "s.altnet.rippletest.net:51233"
	// MainNetURL todo..
	XRPMainNetURL    = "s2.ripple.com:443"
	XRPTestNetAPIURL = "https://testnet.xrpl-labs.com/"
)

func completeXRPTx(txBlob string) error {
	command := XRPComand{
		Id:      2,
		Command: "submit",
		TxBlob:  txBlob,
	}

	conn, _, err := websocket.DefaultDialer.Dial(XRPTestNetURL, nil)
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	err = conn.WriteMessage(websocket.PingMessage, []byte("keepalive"))
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.WebsocketPingError, err)
	}

	err = conn.WriteJSON(command)

	err = conn.WriteMessage(websocket.PingMessage, []byte("keepalive"))
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.WebsocketWrittingError, err)
	}

	return nil
}

func CompleteXRPPaymentTx(txInputs common.BasicTx) {

}
