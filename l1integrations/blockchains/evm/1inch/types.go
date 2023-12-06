package oneinch

type Protocol [][]struct {
	Name             string  `json:"name"`
	Part             float64 `json:"part"`
	FromTokenAddress string  `json:"fromTokenAddress"`
	ToTokenAddress   string  `json:"toTokenAddress"`
}

type Tx struct {
	// transactions will be sent from this address
	From string `json:"from"`
	// transactions will be sent to our contract address
	To string `json:"to"`
	// call data
	Data string `json:"data"`
	// amount of ETH (in wei) will be sent to the contract address
	Value string `json:"value"`
	// gas price in wei
	GasPrice string `json:"gasPrice"`
	// estimated amount of the gas limit, increase this value by 25%
	Gas int64 `json:"gas"`
}

type Token struct {
	Symbol   string `json:"symbol"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Decimals int64  `json:"decimals"`
	LogoURI  string `json:"logoURI"`
}

type SwapResponse struct {
	// parameters of a token to sell
	FromToken Token `json:"fromToken"`
	// parameters of a token to buy
	ToToken Token `json:"ToToken"`
	// input amount of fromToken in minimal divisible units
	ToTokenAmount string `json:"toTokenAmount"`
	// result amount of toToken in minimal divisible units
	FromTokenAmount string `json:"fromTokenAmount"`
	// route of the trade
	Protocols []Protocol `json:"protocols"`
	// transaction data
	Tx Tx `json:"tx"`
}

type QuoteResponse struct {
	// parameters of a token to sell
	FromToken Token `json:"fromToken"`
	// parameters of a token to buy
	ToToken Token `json:"ToToken"`
	// input amount of fromToken in minimal divisible units
	ToTokenAmount string `json:"toTokenAmount"`
	// result amount of toToken in minimal divisible units
	FromTokenAmount string `json:"fromTokenAmount"`
	// route of the trade
	Protocols []Protocol `json:"protocols"`

	EstimatedGas int64 `json:"estimatedGas"`
}
