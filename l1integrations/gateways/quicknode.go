package gateways

type QuicknodeRequest struct {
	Jsonrpc string      `json:"jsonrpc"`
	Id      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type AvaxParams struct {
	Address string `json:"address"`
	AssetID string `json:"assetID"`
}

type UTXOParams struct {
	Addresses   []string `json:"addresses"`
	Limit       int      `json:"limit"`
	SourceChain string   `json:"sourceChain"`
	Encoding    string   `json:"encoding"`
}

type IssueTxParams struct {
	Tx       string `json:"tx"`
	Encoding string `json:"encoding"`
}

type QuicknodeResponse struct {
	Jsonrpc string            `json:"jsonrpc"`
	Id      int               `json:"id"`
	Result  AvalancheResponse `json:"result"`
}

type AvalancheResponse struct {
	Balance            string           `json:"balance"`
	Unlocked           string           `json:"unlocked"`
	LockedStakeable    string           `json:"lockedStakeable"`
	LockedNotStakeable string           `json:"lockedNotStakeable"`
	UTXOIDs            []AvalancheUTXOS `json:"utxoIDs"`
	NumFetched         string           `json:"numFetched"`
	UTXOs              []string         `json:"utxos"`
	EndIndex           EndIndex         `json:"endIndex"`
	Encoding           string           `json:"encoding"`
	TxID               string           `json:"txID"`
	Staked             string           `json:"staked"`
}

type AvalancheUTXOS struct {
	TxID        string `json:"txID"`
	OutputIndex int    `json:"outputIndex"`
}

type EndIndex struct {
	Address string `json:"string"`
	UTXO    string `json:"utxo"`
}
