package near

import (
	"bytes"
	"encoding/json"
	"finco/l1integration/common"
	"fmt"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	TXCommitMethod = "broadcast_tx_commit"
)

var nearAPIUrl = common.L1Configurations.Near.Testnet

func formatRPCErrorResponse(errresp *ErrorResponse) error {
	return fmt.Errorf("Code : %v, Name: %v, Cause: %v", errresp.Name, errresp.Code, errresp.Cause.Name)
}

func RPCCall(method string, params interface{}) (RPCResponse, error) {
	message := RPCMesssage{
		JsonRPC: "2.0",
		Id:      "dontcare",
		Method:  method,
		Params:  params,
	}
	fmt.Printf("Complete RPC message: %v", message)
	serializedBody, err := json.Marshal(message)
	successResponse := RPCResponse{}
	errorResponse := RPCErrorResponse{}
	if err != nil {
		fmt.Printf("%v\n", err)
		return successResponse, err
	}

	req, _ := http.NewRequest(http.MethodPost, nearAPIUrl, bytes.NewBuffer(serializedBody))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%v\n", err)
		return successResponse, err
	}
	data, _ := ioutil.ReadAll(resp.Body)
	// At first we tring to read as error response.
	err = json.Unmarshal(data, &errorResponse)
	if err != nil {
		fmt.Printf("%v\n", err)
		return successResponse, err
	}
	if errorResponse.Error.Code != 0 {
		log.Info("ERROR DATA", errorResponse)
		return successResponse, formatRPCErrorResponse(&errorResponse.Error)
	}

	// After passing error checking we tring to unmarshal our result
	err = json.Unmarshal(data, &successResponse)
	if err != nil {
		fmt.Printf("%v\n", err)
		return successResponse, err
	}
	return successResponse, nil
}

func getBlock(isLast bool, blockId string) (BlockResult, error) {
	params := make(map[string]string)
	blockResult := BlockResult{}
	if isLast {
		params["finality"] = "final"
	} else {
		params["block_id"] = blockId
	}

	lastBlockResponse, err := RPCCall("block", params)
	if err != nil {
		return blockResult, fmt.Errorf("%v", err)
	}
	serializedResult, err := json.Marshal(lastBlockResponse.Result)
	if err != nil {
		return blockResult, err
	}

	err = json.Unmarshal(serializedResult, &blockResult)
	if err != nil {
		return blockResult, err
	}

	return blockResult, nil
}

func GetLastBlock() (BlockResult, error) {
	return getBlock(true, "")
}

func GetBlockById(blockId string) (BlockResult, error) {
	return getBlock(false, blockId)
}

func GetAccountStateOf(accountId string, publicKey string) (ViewAccessKeyResponse, error) {

	var viewAKeyResp ViewAccessKeyResponse
	req := ViewAccessKeyRequest{
		RequestType: "view_access_key",
		Finality:    "final",
		AccountId:   accountId,
		PublicKey:   publicKey,
	}
	resp, err := RPCCall("query", req)
	if err != nil {
		return viewAKeyResp, err
	}

	serializedResult, err := json.Marshal(resp.Result)
	if err != nil {
		return viewAKeyResp, err
	}

	err = json.Unmarshal(serializedResult, &viewAKeyResp)
	if err != nil {
		return viewAKeyResp, err
	}
	fmt.Printf("Block hash view: %v", viewAKeyResp.BlockHash)

	return viewAKeyResp, nil
}
