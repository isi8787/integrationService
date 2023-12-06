package models

// ECDSAThresholdSignatureTransaction compatible structure for custody
// service backend
type ECDSAThresholdSignatureTransaction struct {
	UserID      string `json:"userID"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	MessageHash string `json:"messageHash"`
	TokenId     string `json:"tokenId"`
	Signature   string `json:"signature"`
}

// TokenTransaction common object for transfering from one address to another.
type TokenTransaction struct {
	FromAddress string  `json:"fromAddress"`
	ToAddress   string  `json:"toAddress"`
	Value       float64 `json:"value"`
	Signature   string  `json:"signature"`
}

type BroadcastMessage struct {
	MessageHash string `json:"messageHash"`
	UserId      string `json:"userId"`
	TokenId     string `json:"tokenId"`
	Broadcast   string `json:"broadcast, omitempty"`
}

type InfuraResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
