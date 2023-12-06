package uni

import (
	"errors"
	"math"
	"math/big"
	"time"

	evm_erc20 "finco/l1integration/blockchains/evm/erc20"

	coreEntities "github.com/daoleno/uniswap-sdk-core/entities"
	"github.com/daoleno/uniswapv3-sdk/constants"
	"github.com/daoleno/uniswapv3-sdk/entities"
	"github.com/daoleno/uniswapv3-sdk/examples/contract"
	"github.com/daoleno/uniswapv3-sdk/periphery"
	sdkutils "github.com/daoleno/uniswapv3-sdk/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func FloatToBigInt(amount float64, decimals int) *big.Int {
	fAmount := new(big.Float).SetFloat64(amount)
	fi, _ := new(big.Float).Mul(fAmount, big.NewFloat(math.Pow10(decimals))).Int(nil)
	return fi
}

func BigIntToFloat(amount *big.Int, decimals int) float64 {
	fAmount := new(big.Float).SetInt(amount)
	fi, _ := new(big.Float).Mul(fAmount, big.NewFloat(math.Pow10(-decimals))).Float64()
	return fi
}

func ExactInputSingleRouterV1(client *ethclient.Client,
	fromAddress common.Address,
	swapFee int64,
	tokenIn evm_erc20.TokenDescription,
	amountIn float64,
	tokenOut evm_erc20.TokenDescription) (common.Address, []byte, error) {

	// ContractV3Factory
	uniswapv3Factory, err := contract.NewUniswapv3Factory(common.HexToAddress("0x1F98431c8aD98523631AE4a59f267346ea31F984"), client)
	if err != nil {
		return common.Address{}, nil, err
	}
	uniswapv3FactoryRaw := &contract.Uniswapv3FactoryRaw{Contract: uniswapv3Factory}

	swapFeeBigInt := big.NewInt(swapFee)

	var outGetPool []interface{}
	err = uniswapv3FactoryRaw.Call(nil, &outGetPool, "getPool", tokenIn.Address, tokenOut.Address, swapFeeBigInt)
	if err != nil {
		return common.Address{}, nil, err
	}
	if 0 == len(outGetPool) {
		return common.Address{}, nil, errors.New("no pool is found")
	}
	poolAddress := outGetPool[0].(common.Address)
	if poolAddress == (common.Address{}) {
		return common.Address{}, nil, errors.New("no pool is found")
	}

	//gasPrice, err := client.SuggestGasPrice(context.Background())
	//gasPrice := ethTransaction.FloatToBigInt(1.879053, 12) // this is a sample value from a successful tx example

	if nil != err {
		return common.Address{}, nil, err
	}

	// fmt.Println("pool address: ", poolAddress)
	uniswapV3Pool, err := contract.NewUniswapv3Pool(poolAddress, client)
	if err != nil {
		return common.Address{}, nil, err
	}

	liquidity, err := uniswapV3Pool.Liquidity(nil)
	if err != nil {
		return common.Address{}, nil, err
	}

	slot0, err := uniswapV3Pool.Slot0(nil)
	if err != nil {
		return common.Address{}, nil, err
	}

	pooltick, err := uniswapV3Pool.Ticks(nil, big.NewInt(0))
	if err != nil {
		return common.Address{}, nil, err
	}

	feeAmount := constants.FeeAmount(uint64(swapFee))
	ticks := []entities.Tick{
		{
			Index: entities.NearestUsableTick(sdkutils.MinTick,
				constants.TickSpacings[feeAmount]),
			LiquidityNet:   pooltick.LiquidityNet,
			LiquidityGross: pooltick.LiquidityGross,
		},
		{
			Index: entities.NearestUsableTick(sdkutils.MaxTick,
				constants.TickSpacings[feeAmount]),
			LiquidityNet:   pooltick.LiquidityNet,
			LiquidityGross: pooltick.LiquidityGross,
		},
	}

	tickListDataProvider, err := entities.NewTickListDataProvider(ticks, constants.TickSpacings[feeAmount])
	if err != nil {
		return common.Address{}, nil, err
	}

	tokenInDecimal, err := evm_erc20.GetTokenDecimal(common.HexToAddress(tokenIn.Address), client)
	if err != nil {
		return common.Address{}, nil, err
	}

	tokenOutDecimal, err := evm_erc20.GetTokenDecimal(common.HexToAddress(tokenOut.Address), client)
	if err != nil {
		return common.Address{}, nil, err
	}

	tokenInEntity := coreEntities.NewToken(tokenIn.BlockchainID, common.HexToAddress(tokenIn.Address), uint(tokenInDecimal), tokenIn.Symbol, tokenIn.Name)
	tokenOutEntity := coreEntities.NewToken(tokenOut.BlockchainID, common.HexToAddress(tokenOut.Address), uint(tokenOutDecimal), tokenOut.Symbol, tokenOut.Name)

	poolEntity, err := entities.NewPool(tokenInEntity,
		tokenOutEntity,
		constants.FeeAmount(uint64(swapFee)),
		slot0.SqrtPriceX96,
		liquidity,
		int(slot0.Tick.Int64()),
		tickListDataProvider)

	if err != nil {
		return common.Address{}, nil, err
	}

	routeEntity, err := entities.NewRoute([]*entities.Pool{poolEntity}, tokenInEntity, tokenOutEntity)
	if err != nil {
		return common.Address{}, nil, err
	}

	bigAmountIn := FloatToBigInt(amountIn, int(tokenInEntity.Decimals()))

	//1%
	slippageTolerance := coreEntities.NewPercent(big.NewInt(1), big.NewInt(1))

	currentTimePlus5Minutes := time.Now().Add(time.Minute * time.Duration(5)).Unix()
	deadlineCurrentTimePlus5Minutes := big.NewInt(currentTimePlus5Minutes)

	tradeEntity, err := entities.FromRoute(routeEntity, coreEntities.FromRawAmount(tokenInEntity, bigAmountIn), coreEntities.ExactInput)
	if err != nil {
		return common.Address{}, nil, err
	}

	params, err := periphery.SwapCallParameters([]*entities.Trade{tradeEntity}, &periphery.SwapOptions{
		SlippageTolerance: slippageTolerance,
		Recipient:         fromAddress,
		Deadline:          deadlineCurrentTimePlus5Minutes,
	})
	if err != nil {
		return common.Address{}, nil, err
	}

	// ContractV3SwapRouterV1
	swapRouterAddress := common.HexToAddress("0xE592427A0AEce92De3Edee1F18E0157C05861564")

	// gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
	// 	From:     fromAddress,
	// 	To:       &swapRouterAddress,
	// 	GasPrice: gasPrice,
	// 	Value:    bigAmountIn,
	// 	Data:     params.Calldata,
	// })
	// if err != nil {
	// 	return err
	// }

	//gasLimit := uint64(15 * 21000)

	callData := params.Calldata

	return swapRouterAddress, callData, nil
}
