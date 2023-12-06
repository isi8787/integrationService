package common

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/viper"
)

// Configurations exported
type Configurations struct {
	Server      ServerConfigurations
	Infura      InfuraConfigurations
	Ethereum    EthereumConfigurations
	Bitcoin     BitcoinConfigurations
	Algorand    AlgorandConfigurations
	Blockdaemon BlockdaemonConfigurations
	Quicknode   QuicknodeConfigurations
	Near        NEARConfigurations
	BSC         BSCConfiguration
	Polygon     PolygonConfiguration
	ChainIDs    ChinIDs
}

// ServerConfigurations exported
type ServerConfigurations struct {
	Port string
}

// InfuraConfigurations exported
type InfuraConfigurations struct {
	Mainnet string
	Goerli  string
	Fuji    string
}

// EthereumConfigurations exported
type EthereumConfigurations struct {
	ChainId               int
	EtherscanAPIKEY       string
	EtherscanURL          string
	StakingContract       string
	EtherscanURLGasOracle string
	OneInchApi            string
}

// BitcoinConfigurations exported
type BitcoinConfigurations struct {
	ChainId string
}

// AlgorandConfigurations exported
type AlgorandConfigurations struct {
	ChainId string
	Uri     string
	Token   string
}

// BlockdaemonConfigurations exported
type BlockdaemonConfigurations struct {
	AccessToken string
	Bitcoin     BlockdaemonBitcoin
}

type BlockdaemonBitcoin struct {
	Uri string
}

// InfuraConfigurations exported
type QuicknodeConfigurations struct {
	Fuji AvalancheConfigurations
}

// AlgorandConfigurations exported
type AvalancheConfigurations struct {
	XChain string
	PChain string
	CChain string
}

type NEARConfigurations struct {
	Testnet string
	Mainnet string
}

type BSCConfiguration struct {
	Testnet       string
	Mainnet       string
	BscScanUrl    string
	BscScanApiKey string
	OneInchApi    string
}

type PolygonConfiguration struct {
	Testnet           string
	Mainnet           string
	PolygonScanUrl    string
	PolygonScanApiKey string
	OneInchApi        string
}

type ChinIDs struct {
	Ethereum  EthereumChainIDs
	BSC       BSCChainIDs
	Polygon   PolygonChainIDs
	Avalanche AvalancheChainIDs
}

type EthereumChainIDs struct {
	MainNet int64
	TestNet int64
}

type BSCChainIDs struct {
	MainNet int64
	TestNet int64
}

type PolygonChainIDs struct {
	MainNet int64
	TestNet int64
}

type AvalancheChainIDs struct {
	MainNet int64
	TestNet int64
}

var L1Configurations = LoadConfig()

func LoadConfig() Configurations {
	var configName string
	if GloabalENVVars.WorkingEnvironment == "development" {
		configName = "dev"
	} else if GloabalENVVars.WorkingEnvironment == "production" {
		configName = "prod"
	} else {
		log.Panic("Envioronment Configuration Not Valid")
	}
	// Set the file name of the configurations file
	viper.SetConfigName("config_" + configName)

	// Set the path to look for the configurations file
	viper.AddConfigPath(".")

	// Enable VIPER to read Environment Variables
	viper.AutomaticEnv()

	viper.SetConfigType("yaml")

	var configuration Configurations

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s", err)
	}

	err := viper.Unmarshal(&configuration)
	if err != nil {
		fmt.Printf("Unable to decode into struct, %v", err)
	}

	fmt.Printf("Configurations %v\n", configuration)

	return configuration
}

// Getting once all env variables to avoiding future fatals.
func GetENVVars() *ENVConfigs {
	getOrFatal := func(envVarName string) string {
		variable, ok := os.LookupEnv(envVarName)
		if !ok {
			log.Fatal("missing environment variable: ", envVarName)
		}
		return variable
	}

	env := ENVConfigs{}
	env.WorkingEnvironment = getOrFatal(WorkingEnvironment)
	env.MongoDbConnectionString = getOrFatal(MongoDbConnectionString)
	env.MongoDatabase = getOrFatal(MongoDatabase)
	env.AccountRecordsCollection = getOrFatal(AccountRecordsCollection)
	env.MongoTxCollection = getOrFatal(MongoTxCollection)
	env.MongoStakeTxCollection = getOrFatal(MongoStakeTxCollection)
	env.EtherumCollectionName = getOrFatal(EtherumCollectionName)
	env.BitcoinCollectionName = getOrFatal(BitcoinCollectionName)
	env.AvalancheCollectionName = getOrFatal(AvalancheCollectionName)
	env.AlgorandCollectionName = getOrFatal(AlgorandCollectionName)
	env.NEARProtocolCollectionName = getOrFatal(NEARProtocolCollectionName)
	env.CardanoCollectionName = getOrFatal(CardanoCollectionName)
	env.BSCCollectionName = getOrFatal(BSCCollectionName)
	env.PolygonCollectionName = getOrFatal(PolygonCollectionName)
	env.ParticioantID = getOrFatal(ParticioantID)
	env.AzureClinetID = getOrFatal(AzureClinetID)
	env.AzureClientSecret = getOrFatal(AzureClientSecret)
	env.AzureTenantID = getOrFatal(AzureTenantID)
	env.AzureKeyVaultURL = getOrFatal(AzureKeyVaultURL)
	env.UBIAccessToken = getOrFatal(UBIAccessToken)
	env.InfuraUrl = getOrFatal(InfuraURL)
	env.GinMode = getOrFatal(GinMode)
	env.RedisHost = getOrFatal(RedisHost)
	env.RedisPort = getOrFatal(RedisPort)
	env.KeySharesCollectionName = getOrFatal(KeySharesCollectionName)
	env.CustodyServiceKSMKey = getOrFatal(CustodyServiceKSMKey)
	env.RegionDeploy = getOrFatal(RegionDeploy)

	return &env
}
