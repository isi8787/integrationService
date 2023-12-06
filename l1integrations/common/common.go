package common

import (
	"math/big"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// /BasicTx is structure for sending tokens from one address to another
type BasicTx struct {
	UserId        string     `bson:"userId"`        // userId associated with account
	BlockchainId  string     `bson:"blockchainId"`  // blockchainId is the symbol for a specific blockchain, this is used to link credentials from L1 to ERC20 or ERC721 tokens
	TokenId       string     `bson:"tokenId"`       // tokenId is the symbol for specific asset ETH, BTC, ERC20 symbol
	OriginChain   string     `bson:"originChain"`   // Identifier for blockchain supporting multiple chains
	AccountName   string     `bson:"accountName"`   // accountName is the user defined nickname for a specific set of credentials
	Value         string     `bson:"value"`         // value being transfered by transaction to target account
	ToAddress     string     `bson:"toAddress"`     // toAddress is recipient hex encoded address
	FullTx        string     `bson:"fullTx"`        // fullTx is the JSON stringified transaction that is submitted to target blockchain
	TxHash        string     `bson:"txHash"`        // txHash is the tx hash used to identify transaction
	ApproveFullTx string     `bson:"fullTxApprove"` // fullTxApprove is the JSON stringified approve transaction that is submitted to target blockchain
	Status        string     `bson:"status"`        // status tracks transaction status from generation to signing to completion
	Inputs        []TxInputs `bson:"inputs"`        // for mutli input transactions we need to process multiple singature
	Receipt       string     `bson:"receipt"`       //
	Data          string     `bson:"data"`          // data field to support smart contract execution
	FromAddress   string     `bson:"fromAddress"`   //
	Fee           float64    `bson:"fee"`           // Prepared fee for current tx.
	Amount        float64    `bson:"amount"`        // amount after posible deduction of fee.
	SCAddress     string     `bson:"scAddress"`     // smart contract address: used for ERC20 or BEP20 transactions
}

// /StakeTx is structure for staking ethreum to beacon chain
type StakeTx struct {
	UserId                string     `bson:"userId"`                // userId associated with account
	BlockchainId          string     `bson:"blockchainId"`          // blockchainId is the symbol for a specific blockchain, this is used to link credentials from L1 to ERC20 or ERC721 tokens
	TokenId               string     `bson:"tokenId"`               // tokenId is the symbol for specific asset ETH, BTC, ERC20 symbol
	AccountName           string     `bson:"accountName"`           // accountName is the user defined nickname for a specific set of credentials
	Value                 string     `bson:"value"`                 // value being transfered by transaction to target account
	ValidatorAddress      string     `bson:"validatorAddress"`      // toAddress is recipient hex encoded address
	WithdrawalCredentials string     `bson:"withdrawalCredentials"` //
	DepositSignature      string     `bson:"depositSignature"`      //
	DepositDataRoot       string     `bson:"depositDataRoot"`       //
	FullTx                string     `bson:"fullTx"`                // fullTx is the JSON stringified transaction that is submitted to target blockchain
	TxHash                string     `bson:"txHash"`                // txHash is the tx hash used to identify transaction
	Status                string     `bson:"status"`                // status tracks transaction status from generation to signing to completion
	Receipt               string     `bson:"receipt"`               //
	Inputs                []TxInputs `bson:"inputs"`                // for mutli input transactions we need to process multiple singature
}

// ETHAccounts is a structure for returning to wallet the balances associated with a users ETH blockchain holdings
type ETHAccounts struct {
	Address       string            `json:"address"`       // hex string address on ETH
	Balance       string            `json:"balance"`       // ETH balance
	ERC20Balances map[string]string `json:"erc20Balances"` // ERC20 balance for supported tokens
}

// BTCAccounts is a structure for returning to wallet the balances associated with a users BTC address
type AccountData struct {
	Address      string `json:"address"` // string address on BTC
	Balance      string `json:"balance"` // BTC balance
	StakeBalance string `json:"stakeBalance,omitempty"`
}

type SigningRounds struct {
	Round      string // tracks which ECDSA MPC round is being processed
	Identifier string // 1 is for custody service, 2 is for escrow service, 3 is for mobile or other client
	Message    string // signing broadcast from other participant during ECDSA MPC rounds
}

type AccountRecord struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"` //mongoDB object id created when item inserted to DB
	UserId       string             `bson:"userId"`        // userId created during registration in active directory
	AccountName  string             `bson:"accountName"`   // accountName is the user defined nickname for a specific set of credentials
	BlockchainId string             `bson:"blockchainId"`  // blockchainId is the symbol for a specific blockchain, this is used to link credentials from L1 to ERC20 or ERC721 tokens
}

type InfuraResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// KeyShare represents stored key share data and identifying information
type KeyShare struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"` //mongoDB object id created when item inserted to DB
	UserId       string             `bson:"userId"`        // userId created during registration in active directory
	TokenId      string             `bson:"tokenId"`       // tokenId is the symbol for specific asset ETH, BTC, ERC20 symbol
	AccountName  string             `bson:"accountName"`   // accountName is the user defined nickname for a specific set of credentials
	BlockchainId string             `bson:"blockchainId"`  // blockchainId is the symbol for a specific blockchain, this is used to link credentials from L1 to ERC20 or ERC721 tokens
	ShareData    ECDSAParticipant   `bson:"shareData"`     // shareData is participant specific MPC sensitive data
}

type TxInputs struct {
	Hash       string `json:"hash"`
	InputIndex int    `json:"inputIndex"`
	Signature  string `json:"signature"` // ECDSA or EDDSA
}

type TxSignedInputs struct {
	Inputs []TxInputs `json:"inputs"`
}

type EDDSAShare struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`          //mongoDB object id created when item inserted to DB
	UserId       string             `bson:"userId,omitempty"`       // userId created during registration in active directory
	AccountName  string             `bson:"accountName,omitempty"`  // accountName is the user defined nickname for a specific set of credentials
	BlockchainId string             `bson:"blockchainId,omitempty"` // blockchainId is the symbol for a specific blockchain, this is used to link credentials from L1 to ERC20 or ERC721 tokens
	TokenId      string             `bson:"tokenId,omitempty"`      // tokenId
	PK           string             `bson:"pk,omitempty"`
	SigShare     string             `bson:"sigShare,omitempty"`
	EscrowShare  string             `bson:"escrowShare,omitempty"`
	Address      string             `bson:"address,omitempty"`
}

// EcdsaSignature represents a (composite) digital signature
type EcdsaSignature struct {
	V    int
	R, S *big.Int
}

type ECDSAParticipant struct {
	PK          string            `bson:"pk"`
	Share       string            `bson:"share"`
	PubShares   map[uint32]string `bson:"pubshares"`
	PaillierKey string            `bson:"paillierKey"`
	PubKeys     map[uint32]string `bson:"pubkeys"`
}

type EtherumAddressNonce struct {
	AddressHex string   `bson:"address"`
	LastNonces []uint64 `bson:"nonce"`
}

type NEARAccountNonce struct {
	Address string `bson:"address"`
	Nonce   uint64 `bson:"nonce"`
}

type BitcoinAddressUTXO struct {
	Address   string          `bson:"address"`
	UsedUTXOS map[string]bool `bson:"utxos"` // bool is dumy value, like std::set<std::string>
}

type GasFee struct {
	SafeFee    *big.Int `json:"safe"`
	ProposeFee *big.Int `json:"propose"`
	FastFee    *big.Int `json:"fast"`
}

type ChainsFees struct {
	BTC   GasFee `json:"btc"`
	ETH   GasFee `json:"eth"`
	AVAX  GasFee `json:"avax"`
	ALGO  GasFee `json:"algo"`
	MATIC GasFee `json:"matic"`
	BNB   GasFee `json:"bnb"`
}

type Database struct {
	AccountRecords    *mongo.Collection
	Transactions      *mongo.Collection
	StakeTransactions *mongo.Collection
	Ethereum          *mongo.Collection
	Bitcoin           *mongo.Collection
	Avalanche         *mongo.Collection
	Algorand          *mongo.Collection
	NEARProtocol      *mongo.Collection
	Cardano           *mongo.Collection
	BSC               *mongo.Collection
	Polygon           *mongo.Collection
	GasFees           *mongo.Collection
	KeyShares         *mongo.Collection
}

type ENVConfigs struct {
	WorkingEnvironment         string
	MongoDbConnectionString    string
	MongoDatabase              string
	AccountRecordsCollection   string
	MongoTxCollection          string
	MongoStakeTxCollection     string
	EtherumCollectionName      string
	BitcoinCollectionName      string
	AvalancheCollectionName    string
	AlgorandCollectionName     string
	NEARProtocolCollectionName string
	CardanoCollectionName      string
	BSCCollectionName          string
	PolygonCollectionName      string
	KeySharesCollectionName    string
	ParticioantID              string
	AzureClinetID              string
	AzureClientSecret          string
	AzureTenantID              string
	AzureKeyVaultURL           string
	UBIAccessToken             string
	InfuraUrl                  string
	GinMode                    string
	RedisHost                  string
	RedisPort                  string
	CustodyServiceKSMKey       string
	RegionDeploy               string
}

var GloabalENVVars *ENVConfigs = GetENVVars()

type Exception struct {
	Code      int    `json:"code"`
	ErrorType string `json:"type"`
	Message   string `json:"message"`
}

type ApiError struct {
	Status bool         `json:"status"`
	Err    ErrorDetails `json:"error"`
}

type ErrorDetails struct {
	Type    string      `json:"type"`
	Message interface{} `json:"message"`
}

type ApiSuccess struct {
	Status bool        `json:"status"`
	Result interface{} `json:"result"`
}

type SuccessDetails struct {
	Message string `json:"message"`
}

type AWSStorage struct {
	Index string   `bson:"index"`
	Value []string `bson:"value"`
}
