package uni

import (
	"errors"
	evm_erc20 "finco/l1integration/blockchains/evm/erc20"
	"math/big"

	"github.com/daoleno/uniswapv3-sdk/examples/contract"
	"github.com/daoleno/uniswapv3-sdk/examples/helper"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func GetRate(client *ethclient.Client,
	swapFee int64,
	tokenIn evm_erc20.TokenDescription,
	amountIn float64,
	tokenOut evm_erc20.TokenDescription) (float64, error) {

	swapFees := [3]int64{100, 500, 3000}

	amountOut := float64(0)
	var err error

	for i := 0; i < len(swapFees); i++ {
		amount, err := getRate(client, swapFees[i], tokenIn, amountIn, tokenOut)

		if err == nil && amount > amountOut {
			amountOut = amount
		}
	}

	return amountOut, err
}

func getRate(client *ethclient.Client,
	swapFee int64,
	tokenIn evm_erc20.TokenDescription,
	amountIn float64,
	tokenOut evm_erc20.TokenDescription) (float64, error) {

	uniswapv3Factory, err := contract.NewUniswapv3Factory(common.HexToAddress(helper.ContractV3Factory), client)
	if err != nil {
		return 0, err
	}

	uniswapv3FactoryRaw := &contract.Uniswapv3FactoryRaw{Contract: uniswapv3Factory}

	swapFeeBigInt := big.NewInt(swapFee)
	sqrtPriceLimitX96 := big.NewInt(0)

	var outGetPool []interface{}
	err = uniswapv3FactoryRaw.Call(nil, &outGetPool, "getPool", common.HexToAddress(tokenIn.Address), common.HexToAddress(tokenOut.Address), swapFeeBigInt)
	if err != nil {
		return 0, err
	}
	if len(outGetPool) == 0 {
		return 0, errors.New("no pool is found")
	}
	poolAddress := outGetPool[0].(common.Address)
	if poolAddress == (common.Address{}) {
		return 0, errors.New("no pool is found")
	}

	uniswapv3Quoter, err := contract.NewUniswapv3Quoter(common.HexToAddress(helper.ContractV3Quoter), client)
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

	bigAmountIn := FloatToBigInt(amountIn, int(tokenInDecimal))

	var outQuote []interface{}
	uniswapv3QuoterRaw := &contract.Uniswapv3QuoterRaw{Contract: uniswapv3Quoter}
	err = uniswapv3QuoterRaw.Call(nil, &outQuote, "quoteExactInputSingle", common.HexToAddress(tokenIn.Address), common.HexToAddress(tokenOut.Address), swapFeeBigInt, bigAmountIn, sqrtPriceLimitX96)
	if err != nil {
		return 0, err
	}

	return BigIntToFloat(outQuote[0].(*big.Int), int(tokenOutDecimal)), nil
}
