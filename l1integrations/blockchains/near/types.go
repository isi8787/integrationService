package near

import (
	"crypto/sha256"
	"finco/l1integration/errors"

	"github.com/near/borsh-go"
	neartx "github.com/textileio/near-api-go/transaction"
)

type BlockHeader struct {
	Height                int           `json:"height"`
	EpochID               string        `json:"epoch_id"`
	NextEpochID           string        `json:"next_epoch_id"`
	Hash                  string        `json:"hash"`
	PrevHash              string        `json:"prev_hash"`
	PrevStateRoot         string        `json:"prev_state_root"`
	ChunkReceiptsRoot     string        `json:"hunk_receipts_root"`
	ChunkHeadersRoot      string        `json:"chunk_headers_root"`
	ChunkTxRoot           string        `json:"chunk_tx_root"`
	OutcomeToot           string        `json:"outcome_root"`
	ChunksIncluded        int           `json:"chunks_included"`
	ChallengesRoot        string        `json:"challenges_root"`
	Timestamp             int           `json:"timestamp"`
	TimestampNanosec      string        `json:"timestamp_nanosec"`
	RandomValue           string        `json:"random_value"`
	ValidatorProposals    []interface{} `json:"validator_proposals"` // TODO: what with this?
	ChunkMask             []bool        `json:"chunk_mask"`
	GasPrice              string        `json:"gas_price"`
	RentPaid              string        `json:"rent_paid"`
	ValidatorReward       string        `json:"validator_reward"`
	TotalSupply           string        `json:"total_supply"`
	ChallengesResult      []interface{} `json:"challenges_result"` // TODO: what with this?
	LastFinalBlock        string        `json:"last_final_block"`
	LastDsFinalBlock      string        `json:"last_ds_final_block"`
	NextBpHash            string        `json:"next_bp_hash"`
	BlockMerkleRoot       string        `json:"block_merkle_root"`
	Approvals             []string      `json:"approvals"`
	Signature             string        `json:"signature"`
	LatestProtocolVersion int           `json:"latest_protocol_version"`
}
type Chunk struct {
	ChunkHash            string        `json:"chunk_hash"`
	PrevBlockHash        string        `json:"prev_block_hash"`
	OutcomeRoot          string        `json:"outcome_root"`
	PrevStateRoot        string        `json:"prev_state_root"`
	EncodedMerkleRoot    string        `json:"encoded_merkle_root"`
	EncodedLength        int           `json:"encoded_length"`
	HeightCreated        int           `json:"height_created"`
	HeightIncluded       int           `json:"height_included"`
	ShardID              int           `json:"shard_id"`
	GasUsed              int           `json:"gas_used"`
	GasLimit             int           `json:"gas_limit"`
	RentPaid             string        `json:"rent_paid"`
	ValidatorReward      string        `json:"validator_reward"`
	BalanceBurnt         string        `json:"balance_burnt"`
	OutgoingReceiptsRoot string        `json:"outgoing_receipts_root"`
	TxRoot               string        `json:"tx_root"`
	ValidatorProposals   []interface{} `json:"validator_proposals"` // TODO: what with this?
	Signature            string        `json:"signature"`
}

type TransactionReceipt struct {
	Actions    interface{} `json:"actions"`
	Hash       string      `json:"hash"`
	Nonce      uint64      `json:"nonce"`
	PublicKey  string      `json:"public_key"`
	ReceiverId string      `json:"receiver_id"`
	Signature  string      `json:"signature"`
	SignerId   string      `json:"signer_id"`
}

type TransactionReceiptResult struct {
	ReceiptOutcoume    interface{}        `json:"receipts_outcome"`
	Status             interface{}        `json:"status"`
	Transaction        TransactionReceipt `json:"transaction"`
	TransactionOutcome interface{}        `json:"transaction_outcome"`
}

type BlockResult struct {
	Author string      `json:"author"`
	Header BlockHeader `json:"header"`
	Chunks []Chunk     `json:"chunks"`
}

type RPCMesssage struct {
	JsonRPC string      `json:"jsonrpc"`
	Id      string      `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type RPCResponse struct {
	JsonRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
	Id      string      `json:"id"`
}

type RPCErrorResponse struct {
	JsonRPC string        `json:"jsonrpc"`
	Error   ErrorResponse `json:"error"`
	Id      string        `json:"id"`
}
type ErrorResponse struct {
	Name    string      `json:"name"`
	Cause   Cause       `json:"cause"`
	Code    int         `json:"code"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
}

type Cause struct {
	Info interface{} `json:"info"`
	Data interface{} `json:"data"`
	Name string      `json:"name"`
}

func GetHashOfNEARTx(transaction neartx.Transaction) ([32]byte, []byte, error) {
	message, err := borsh.Serialize(transaction)
	if err != nil {
		return [32]byte{}, []byte{}, errors.BuildAndLogErrorMsg(errors.TxSerializeError, err)
	}
	return sha256.Sum256(message), message, nil
}

type ViewAccessKeyRequest struct {
	RequestType string `json:"request_type"`
	Finality    string `json:"finality"`
	AccountId   string `json:"account_id"`
	PublicKey   string `json:"public_key"`
}

type ViewAccessKeyResponse struct {
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	Nonce       uint64 `json:"nonce"`
	Permision   string `json:"permission"`
}
