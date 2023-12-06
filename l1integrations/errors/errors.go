package errors

import (
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
)

func BuildErrMsg(errorType string, err error) error {
	return fmt.Errorf("%s : %v", errorType, err)
}

func BuildAndLogErrorMsg(errorType string, err error) error {
	er := BuildErrMsg(errorType, err)
	log.Error(er)
	return er
}

func BuildAndLogErrorMsgWithData(errorType string, err error, args ...interface{}) error {
	log.Error(fmt.Sprintf("Data: %v", args...))
	return BuildAndLogErrorMsg(errorType, err)
}

const (
	MarshallError          = "Error marshalling bytes into structure"
	UnmarshallError        = "Error unmarshalling structure into byte"
	DecodeBodyError        = "Error decoding http request body into structure"
	Base64DecodeError      = "Error decoding base64 encoded string"
	HexDecodeError         = "Error decoding hex encoded string"
	HexEncodeError         = "Error encoding to hex string"
	ReadMPCShareError      = "Error reading custody share"
	HttpRequestError       = "Error executing http request"
	StroingInKVError       = "Error storing secret into key vault"
	DecodingKeyShareErrror = "Error decoding key share from key vault"

	GetPublicKeyError         = "Error getting public key"
	TxBuildError              = "Error building atomic transaction"
	WriteTxError              = "Error writing Tx to DB"
	ReadTxError               = "Error reading Tx to DB"
	UpdateTxError             = "Error update Tx in DB"
	CommitTxError             = "Error commiting Tx to Blockchain"
	ConfirmTxError            = "Error waiting for Tx confirmation"
	GetBalanceError           = "Error querying balance from Blockchain"
	ClientError               = "Error creating client"
	BalanceError              = "Error getting account balance"
	NotEnoughAmountError      = "Error no enough amount"
	UnitConversionError       = "Error converting value"
	CreateTxError             = "Error creating transaction"
	SignatureError            = "Error with signature"
	AddressError              = "Error parsing address"
	InputsError               = "Error processing tx inputs"
	IncorrectInputs           = "Error incorrect inputs"
	GetPendingNocceError      = "Error getting pending nonce"
	TxDecodingError           = "Error decoding tx"
	TxEncoding                = "Error encoding tx"
	InsertAccountRecordError  = "Error inserting account record into db"
	ReadingAccountRecordError = "Error reading account record"
	ClientUserIdEror          = "Error invalid user id"
	KVCClientCreationError    = "Error creating key vault client"
	EmptyInputsError          = "Error empty inputs"

	NonceUpdateError        = "Error updating nonce"
	NonceCountError         = "Error retrieving nonce"
	UTXOUpdateError         = "Error update utxo"
	UTXONotFoundError       = "Error utxo for address not found"
	MultipleMapedUTXOsError = "Error multiple document for same address in DB"

	DBConnectionError     = "Error connecting to DB"
	DBInitializationError = "Error initializing DB"
	DBConfigurationError  = "Error configuring DB"

	InsertingIntoWrongCollectionError = "Error inserting into wrong collection"
	ReadingFromWrongCollectionError   = "Error reading from wrong collection"
	AddingTxIntoDBError               = "Error adding tx into DB"

	WebsocketWrittingError = "Error writing in websocket"
	WebsocketPingError     = "Error pinging through websocket"

	TxSerializeError = "Error serializing tx"

	BlockFrostGatewayError = "Error getting information from blockfrost"
)

func New(message string) error {
	return errors.New(message)
}
