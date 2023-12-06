package common

import (
	"time"
)

// Retry wait time
const RetrySleep = 3 * time.Second

// TODO: need configuration file with list of ERC20 tokens we want to support
// need symbol and smart contract address (smart contract address will be chain specific main vs test)
var Erc20Map map[string]string = map[string]string{
	"QKC":    "0xb2a28A6f755b85eeF3cD41058A5d2A7A398281FC",
	"WEENUS": "0xaFF4481D10270F50f203E0763e2597776068CBc5",
}

// TODO: need configuration file with list of ERC20 tokens we want to support
// need symbol and smart contract address (smart contract address will be chain specific main vs test)
var StakingMap map[string]string = map[string]string{
	"ETH": "0x8c5fecdc472e27bc447696f431e425d02dd46a8c", //GOERLY
}

// Array of support blockchains
var BlockchainsMap map[string]string = map[string]string{
	"ETH":   "ECDSA",
	"BTC":   "ECDSA",
	"BNB":   "ECDSA",
	"MATIC": "ECDSA",
	"ADA":   "EDDSA",
	"ALGO":  "EDDSA",
	"AVAX":  "ECDSA",
	"NEAR":  "EDDSA",
}

// BTC constants
const (
	//pubkeyCompressed   byte = 0x2 // y_bit + x coord
	PubkeyUncompressed byte = 0x4 // x coord + y coord
	//pubkeyHybrid       byte = 0x6 // y_bit + x coord + y coord
)

const (
	ECDSA = "ECDSA"
	EDDSA = "EDDSA"
)

// Basic Transaction States
const (
	TxCreated   = "created"
	TxSubmitted = "submitted"
	TxComplete  = "complete"
	TxRejected  = "rejected"
)

const (
	WorkingEnvironment         = "WORKING_ENVIRONMENT"
	MongoDbConnectionString    = "MongoDbConnectionString"
	MongoDatabase              = "MONGODB_DATABASE"
	AccountRecordsCollection   = "ACCOUNT_RECORDS_COLLECTION"
	MongoTxCollection          = "MONGODB_TX_COLLECTION"
	MongoStakeTxCollection     = "MONGODB_STAKE_TX_COLLECTION"
	EtherumCollectionName      = "ETHERUM_COLLECTION_NAME"
	BitcoinCollectionName      = "BITCOIN_COLLECTION_NAME"
	AvalancheCollectionName    = "AVALANCHE_COLLECTION_NAME"
	AlgorandCollectionName     = "ALGORAND_COLLECTION_NAME"
	NEARProtocolCollectionName = "NEAR_COLLECTION_NAME"
	CardanoCollectionName      = "CARDANO_COLLECTION_NAME"
	BSCCollectionName          = "BSC_COLLECTION_NAME"
	PolygonCollectionName      = "POLYGON_COLLECTION_NAME"
	KeySharesCollectionName    = "KEY_SHARES_COLLECTION_NAME"
	ParticioantID              = "PARTICIPANTID"
	AzureClinetID              = "AZURE_CLIENT_ID"
	AzureClientSecret          = "AZURE_CLIENT_SECRET"
	AzureTenantID              = "AZURE_TENANT_ID"
	AzureKeyVaultURL           = "AZURE_KEYVAULT_URL"
	UBIAccessToken             = "UBI_ACCESS_TOKEN"
	InfuraURL                  = "INFURA_URL"
	GinMode                    = "GIN_MODE"
	GasFees                    = "GAS_FEES_COLLECTION"
	RedisHost                  = "REDIS_HOST"
	RedisPort                  = "REDIS_PORT"
	SignerMongoDatabase        = "SIGNER_MONGODB_DATABASE"
	CustodyServiceKSMKey       = "CUSTODY_SERVICE_KSM_KEY"
	RegionDeploy               = "REGION_DEPLOY"
)
