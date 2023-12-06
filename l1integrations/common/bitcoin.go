package common

type UTXOResponse struct {
	Total int      `json:"total"`
	Data  []UTXOTx `json:"data"`
}

type UTXOTx struct {
	Status  string   `json:"status"`
	IsSpent bool     `json:"is_spent"`
	Value   int64    `json:"value"`
	Mined   UTXOMine `json:"mined"`
}

type UTXOMine struct {
	Index         int    `json:"index"`
	TxId          string `json:"tx_id"`
	Date          int64  `json:"date"`
	BlockId       string `json:"block_id"`
	BlockNumber   int    `json:"block_number"`
	Confirmations int    `json:"confirmations"`
}
