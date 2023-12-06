package blockchains

const (
	Ethereum        = "ETH"
	Bitcoin         = "BTC"
	Algorand        = "ALGO"
	Avalanche       = "AVAX"
	AvalancheCChain = "C"
	AvalancheXChain = "X"
	AvalanchePChain = "P"
	NEARProtocol    = "NEAR"
	Cardano         = "ADA"
	BSC             = "BNB"
	Polygon         = "MATIC"
)

//Avalanche Support Constants

// Configurations from Infura and Quicknode
// var fujiCChainURI string = l1common.L1Configurations.Infura.Fuji
// var fujiChains l1common.AvalancheConfigurations = l1common.L1Configurations.Quicknode.Fuji

const avaxSeperator = "-"
const EVMCodecVersion uint16 = 0
const x2cRateInt64 int64 = 1000000000
const MaxMemoSize = 256
const CodecVersion = 0

// Avax Fuji Chain IDs
var chainIdMap map[string]string = map[string]string{
	"X": "2JVSBoinj9C2J33VntvzYtVJNZdN2NKiwwKjcumHUWEb5DbBrm",
	"P": "11111111111111111111111111111111LpoYY",
	"C": "yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp",
}

// AVAX Standard ID
const avaxID = "U8iRqJoiJm8xZHAacmvYyZVwqQx6uDNtQeP3CQ6fcgQk3JqnK"

// Avax cross chain transaction types
const AvalancheExport = "export"
const AvalancheImport = "import"
const AvalancheAddDelegator = "delegate"
