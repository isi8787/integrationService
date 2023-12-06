package operations

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"finco/l1integration/blockchains"
	l1common "finco/l1integration/common"

	"bitbucket.org/carsonliving/cryptographymodules/kryptology/pkg/core/curves"

	"github.com/ethereum/go-ethereum/common"
)

var tx = l1common.BasicTx{
	UserId:       "test",
	TokenId:      "ETH",
	BlockchainId: "ETH",
	AccountName:  "defaultAccount",
	Value:        "1",
	ToAddress:    "0xba536245A30404A983E120a3d07A7dF260a89669",
	FullTx:       "{\"type\":\"0x0\",\"nonce\":\"0xd\",\"gasPrice\":\"0x12c3045ef\",\"maxPriorityFeePerGas\":null,\"maxFeePerGas\":null,\"gas\":\"0x5208\",\"value\":\"0x2386f26fc10000\",\"input\":\"0x\",\"v\":\"0x0\",\"r\":\"0x0\",\"s\":\"0x0\",\"to\":\"0x019ad7b3a616275df4272adad98a95d07658789e\",\"hash\":\"0x115022a4912ff2b5c2e4f2fb9b22d2f38779fb795011b4fdc0bb5125e984ecef\"}",
	TxHash:       "0xcd2cbae4bd2be4a031042d65c1684a0b3795f0f4a5d6622d942a1a47e37e0f65",
	Status:       "test",
}

var hash = "0xe4bffb33176924ea212a630405b4b44509d20cbaf152c463c88d273ffc37d683"

func TestSubmitTx(t *testing.T) {
	w := httptest.NewRecorder()
	router := NewRouter()

	//var tx models.ECDSAThresholdSignatureTransaction
	payload := strings.NewReader(`{
		"userId":"test",
    	"tokenId":"test",
    	"status": "complete",
		"message":"{\"type\":\"0x0\",\"nonce\":\"0xd\",\"gasPrice\":\"0x12c3045ef\",\"maxPriorityFeePerGas\":null,\"maxFeePerGas\":null,\"gas\":\"0x5208\",\"value\":\"0x2386f26fc10000\",\"input\":\"0x\",\"v\":\"0x0\",\"r\":\"0x0\",\"s\":\"0x0\",\"to\":\"0x019ad7b3a616275df4272adad98a95d07658789e\",\"hash\":\"0x115022a4912ff2b5c2e4f2fb9b22d2f38779fb795011b4fdc0bb5125e984ecef\"}",
		"messageHash":"0xcd2cbae4bd2be4a031042d65c1684a0b3795f0f4a5d6622d942a1a47e37e0f65",
		"signature":"{\"V\":0,\"R\":23863118864871130687084279012709680693169914664167250290279410962712418494821,\"S\":29616609045351480651759929894006580667917738047177191326973422978780862202882}"
	}`)

	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/submitTx", payload))

	if w.Code != 424 {
		t.Error("Did not get expected HTTP status code, got", w.Code)
	}

	var response l1common.InfuraResponse
	json.Unmarshal([]byte(w.Body.String()), &response)

	if response.Message != `nonce too low` {
		t.Error("Error getting response from custody service, got", w.Body.String())
	}

}

func TestPostERC20Tx(t *testing.T) {
	w := httptest.NewRecorder()
	router := NewRouter()

	//var tx models.ECDSAThresholdSignatureTransaction
	payload := strings.NewReader(`{
		"userId":"test",
    	"tokenId":"test",
    	"status": "complete",
		"message":"{\"type\":\"0x0\",\"nonce\":\"0xd\",\"gasPrice\":\"0x12c3045ef\",\"maxPriorityFeePerGas\":null,\"maxFeePerGas\":null,\"gas\":\"0x5208\",\"value\":\"0x2386f26fc10000\",\"input\":\"0x\",\"v\":\"0x0\",\"r\":\"0x0\",\"s\":\"0x0\",\"to\":\"0x019ad7b3a616275df4272adad98a95d07658789e\",\"hash\":\"0x115022a4912ff2b5c2e4f2fb9b22d2f38779fb795011b4fdc0bb5125e984ecef\"}",
		"messageHash":"0xcd2cbae4bd2be4a031042d65c1684a0b3795f0f4a5d6622d942a1a47e37e0f65",
		"signature":"{\"V\":0,\"R\":23863118864871130687084279012709680693169914664167250290279410962712418494821,\"S\":29616609045351480651759929894006580667917738047177191326973422978780862202882}"
	}`)

	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/createERC20/userxx920/OKC", payload))

	if w.Code != 202 {
		t.Error("Did not get expected HTTP status code, got", w.Code)
	}

	if w.Body.String() != `"Success"` {
		t.Error("Error getting response from custody service, got", w.Body.String())
	}

}

func TestCreateNewTx(t *testing.T) {
	w := httptest.NewRecorder()
	router := NewRouter()
	payload := strings.NewReader(`{
		"fromAddress":"0xD7fE4E2Cadd77572504fc5f35F44A9c33df027df",
    	"toAddress":"0x019aD7b3A616275Df4272AdAD98A95d07658789e",
    	"value": 1
	}`)

	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/createNewTx/userxx920", payload))

	if w.Code != 202 {
		t.Error("Did not get expected HTTP status code, got", w.Code)
	}

	if w.Body.String() != `"Success"` {
		t.Error("Error getting response from custody service, got", w.Body.String())
	}

}

func TestETHAccounts(t *testing.T) {
	address := common.HexToAddress(tx.ToAddress)
	ethAccount, err := blockchains.GetETHBalances(address)
	if err != nil {
		t.Error("Error getting address details")
	}

	if ethAccount.Address != tx.ToAddress {
		t.Error("Error address details")
	}

	balance, err := strconv.ParseFloat(ethAccount.Balance, 32)
	if err != nil {
		t.Error("Error calculating balance")
	}

	if balance < 0 {
		t.Error("Balance can not be negative")
	}
}

func TestEtherWeiConversions(t *testing.T) {
	ether := big.NewInt(100)
	wei := blockchains.EtherToWei(ether)
	ether2 := blockchains.WeiToEther(wei)
	etherfloat := new(big.Float).SetInt(ether)

	if etherfloat.Cmp(ether2) != 0 {
		t.Error("Error converting between ether and wei")
	}

}

func TestETHTx(t *testing.T) {
	var pk curves.EcPoint
	pk.UnmarshalJSON([]byte("{\"CurveName\":\"secp256k1\",\"X\":44275936294645438035472289470263284318980676905394845068657475342134730093863,\"Y\":87733352844915594082926128840254106909626624471258463773984411204997513669720}"))

	pubKeyK := ecdsa.PublicKey{
		Curve: pk.Curve,
		X:     pk.X,
		Y:     pk.Y,
	}

	_, err := blockchains.ETHTx(tx, pubKeyK)
	if err != nil {
		t.Error("Error preparing basic Tx")
	}
}
