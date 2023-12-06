package oneinch

import (
	"encoding/json"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
)

func DoSwapRequest(chainId int64, fromTokenAddress string, toTokenAddress string, amount big.Int, fromAddress string, slippage int64) (Tx, error) {
	endpoint, err := get1inchSwapEndpoint(chainId)
	httpRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return Tx{}, err
	}

	httpQuery := httpRequest.URL.Query()
	httpQuery.Add("fromTokenAddress", fromTokenAddress)
	httpQuery.Add("toTokenAddress", toTokenAddress)
	httpQuery.Add("amount", amount.String())
	httpQuery.Add("fromAddress", fromAddress)
	httpQuery.Add("slippage", strconv.FormatInt(slippage, 10))
	httpRequest.URL.RawQuery = httpQuery.Encode()
	resp, err := http.Get(httpRequest.URL.String())
	if err != nil {
		return Tx{}, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}
	defer resp.Body.Close()

	var swapResponse SwapResponse
	if resp.StatusCode >= 400 && resp.StatusCode <= 500 {
		return Tx{}, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Tx{}, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}
	respBody := json.Unmarshal(body, &swapResponse)
	if respBody != nil {
		return Tx{}, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	return Tx{}, nil
}

func get1inchSwapEndpoint(chainId int64) (string, error) {
	if chainId == l1common.L1Configurations.ChainIDs.Ethereum.MainNet {
		return fmt.Sprintf(l1common.L1Configurations.Ethereum.OneInchApi, "swap"), nil
	} else if chainId == l1common.L1Configurations.ChainIDs.BSC.MainNet {
		return fmt.Sprintf(l1common.L1Configurations.BSC.OneInchApi, "swap"), nil
	} else if chainId == l1common.L1Configurations.ChainIDs.Polygon.MainNet {
		return fmt.Sprintf(l1common.L1Configurations.Polygon.OneInchApi, "swap"), nil
	}
	return "", errors.BuildAndLogErrorMsg(errors.EmptyInputsError, fmt.Errorf("invalid chain id%v ", chainId))
}

func DoQuoteRequest(chainId int64, fromTokenAddress string, toTokenAddress string, amount string) (QuoteResponse, error) {
	endpoint, err := get1inchQuoteEndpoint(chainId)
	httpRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return QuoteResponse{}, err
	}

	httpQuery := httpRequest.URL.Query()
	httpQuery.Add("fromTokenAddress", fromTokenAddress)
	httpQuery.Add("toTokenAddress", toTokenAddress)
	httpQuery.Add("amount", amount)
	httpRequest.URL.RawQuery = httpQuery.Encode()

	resp, err := http.Get(httpRequest.URL.String())
	if err != nil {
		return QuoteResponse{}, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}
	defer resp.Body.Close()

	var quoteResponse QuoteResponse
	if resp.StatusCode >= 400 && resp.StatusCode <= 500 {
		return QuoteResponse{}, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return QuoteResponse{}, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}
	respBody := json.Unmarshal(body, &quoteResponse)
	if respBody != nil {
		return QuoteResponse{}, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}
	return quoteResponse, nil
}

func get1inchQuoteEndpoint(chainId int64) (string, error) {
	if chainId == l1common.L1Configurations.ChainIDs.Ethereum.MainNet {
		return fmt.Sprintf(l1common.L1Configurations.Ethereum.OneInchApi, "quote"), nil
	} else if chainId == l1common.L1Configurations.ChainIDs.BSC.MainNet {
		return fmt.Sprintf(l1common.L1Configurations.BSC.OneInchApi, "quote"), nil
	} else if chainId == l1common.L1Configurations.ChainIDs.Polygon.MainNet {
		return fmt.Sprintf(l1common.L1Configurations.Polygon.OneInchApi, "quote"), nil
	}
	return "", errors.BuildAndLogErrorMsg(errors.EmptyInputsError, fmt.Errorf("invalid chain id%v ", chainId))
}
