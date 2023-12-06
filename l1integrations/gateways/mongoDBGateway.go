package gateways

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"finco/l1integration/common"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"bitbucket.org/carsonliving/flowsdk/integrations/flowmongodb"

	log "github.com/sirupsen/logrus"

	flow_aws_kms "bitbucket.org/carsonliving/aws-kms-client"
)

// AWS KSM Client instance
func KSMClient() flow_aws_kms.KMSClient {
	return flow_aws_kms.GetWithDefaultConfig(common.GloabalENVVars.RegionDeploy, common.GloabalENVVars.CustodyServiceKSMKey)
}

// ConnectDB creates a MongoDB client
func ConnectDB() *common.Database {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	c, err := flowmongodb.Connect(ctx, options.Client().ApplyURI(common.GloabalENVVars.MongoDbConnectionString))

	if err != nil {
		log.Fatal(errors.BuildErrMsg(errors.DBInitializationError, err))
	}
	err = c.Ping(ctx, nil)
	if err != nil {
		log.Fatal("error Ping DB: ", errors.BuildErrMsg(errors.DBConnectionError, err))
	}

	var databaseCollections common.Database
	database := c.Database(common.GloabalENVVars.MongoDatabase)
	databaseCollections.AccountRecords = database.Collection(common.GloabalENVVars.AccountRecordsCollection)
	databaseCollections.Transactions = database.Collection(common.GloabalENVVars.MongoTxCollection)
	databaseCollections.StakeTransactions = database.Collection(common.GloabalENVVars.MongoStakeTxCollection)
	databaseCollections.Ethereum = database.Collection(common.GloabalENVVars.EtherumCollectionName)
	databaseCollections.Bitcoin = database.Collection(common.GloabalENVVars.BitcoinCollectionName)
	databaseCollections.Avalanche = database.Collection(common.GloabalENVVars.AvalancheCollectionName)
	databaseCollections.Algorand = database.Collection(common.GloabalENVVars.AlgorandCollectionName)
	databaseCollections.NEARProtocol = database.Collection(common.GloabalENVVars.NEARProtocolCollectionName)
	databaseCollections.Cardano = database.Collection(common.GloabalENVVars.CardanoCollectionName)
	databaseCollections.BSC = database.Collection(common.GloabalENVVars.BSCCollectionName)
	databaseCollections.Polygon = database.Collection(common.GloabalENVVars.PolygonCollectionName)
	databaseCollections.KeyShares = database.Collection(common.GloabalENVVars.KeySharesCollectionName)

	mod := mongo.IndexModel{
		Keys:    bson.M{"txHash": 1}, // index in ascending order or -1 for descending order
		Options: options.Index().SetUnique(true),
	}

	_, err = databaseCollections.Transactions.Indexes().CreateOne(ctx, mod)
	if err != nil {
		log.Fatal(errors.BuildErrMsg(errors.DBConfigurationError, err))
	}

	return &databaseCollections
}

// decrypChunkData
func decrypChunkData(ciphertexts []string) ([]byte, error) {
	var plaintexts [][]byte
	for i := 0; i < len(ciphertexts); i++ {
		decodeb64, err := base64.StdEncoding.DecodeString(ciphertexts[i])
		if err != nil {
			return nil, err
		}

		// Call the Decrypt operation
		output, err := KSM.Decrypt(decodeb64)
		if err != nil {
			return nil, err
		}

		// Append the plaintext to the slice of plaintexts
		plaintexts = append(plaintexts, output)
	}

	plaintext := bytes.Join(plaintexts, []byte(""))
	return plaintext, nil
}

// readShare return target key share based on userid , blockchainid and accountName
func ReadECDSAShare(userId string, blockchainId string, accountName string, keyShareCollection *mongo.Collection) (l1common.KeyShare, error) {
	var keyShare l1common.KeyShare
	keyvaultindex := userId + "-" + blockchainId + "-" + accountName // TODO: need to salt hash to create a more obfuscated index

	var awsKeyObject l1common.AWSStorage
	filter := bson.M{"index": keyvaultindex}

	ctx := context.Background()
	err := keyShareCollection.FindOne(ctx, filter).Decode(&awsKeyObject)
	if err != nil {
		log.Error("Error reading key share from db err:", err)
		return keyShare, err
	}

	keySharebytes, err := decrypChunkData(awsKeyObject.Value)
	if err != nil {
		log.Error("Error decrypting key share from key vault ", err)
		return keyShare, err
	}

	err = json.Unmarshal(keySharebytes, &keyShare)
	if err != nil {
		log.Error("Error decoding key share from key vault ", err)
	}

	return keyShare, nil
}

// readShare return target key share based on userid , blockchainid and accountName
func ReadEDDSAShare(userId string, blockchainId string, accountName string, keyShareCollection *mongo.Collection) (l1common.EDDSAShare, error) {
	var keyShare l1common.EDDSAShare
	keyvaultindex := userId + "-" + blockchainId + "-" + accountName // TODO: need to salt hash to create a more obfuscated index

	var awsKeyObject l1common.AWSStorage
	filter := bson.M{"index": keyvaultindex}

	ctx := context.Background()
	err := keyShareCollection.FindOne(ctx, filter).Decode(&awsKeyObject)
	if err != nil {
		log.Error("Error reading record from db err:", err)
		return keyShare, err
	}

	keySharebytes, err := decrypChunkData(awsKeyObject.Value)
	if err != nil {
		log.Error("Error decrypting key share from key vault ", err)
		return keyShare, err
	}

	err = json.Unmarshal(keySharebytes, &keyShare)
	if err != nil {
		log.Error("Error decoding key share from key vault ", err)
	}

	return keyShare, nil
}

// createAccountRecord saves record of index used to store keyShare
func CreateAccountRecord(userId, blockchainId, accountName string, todoCollection *mongo.Collection) error {
	accounts, _ := ReadAccountRecords(userId, blockchainId, todoCollection)
	if len(accounts) > 0 {
		for _, account := range accounts {
			if account.AccountName == accountName {
				log.Info("Account with same name already exist")
				return nil
			}
		}
	}

	ctx := context.Background()
	_, err := todoCollection.InsertOne(ctx, l1common.AccountRecord{UserId: userId, BlockchainId: blockchainId, AccountName: accountName})
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.InsertAccountRecordError, err)
	}
	return nil
}

// readAccountRecords retrieve records of indexes used to store keyShare
func ReadAccountRecords(userId, blockchainId string, todoCollection *mongo.Collection) ([]l1common.AccountRecord, error) {
	var res []l1common.AccountRecord

	filter := bson.D{{"userId", userId}, {"blockchainId", blockchainId}}

	ctx := context.Background()
	curres, err := todoCollection.Find(ctx, filter)
	if err != nil {
		return res, errors.BuildAndLogErrorMsg(errors.ReadingAccountRecordError, err)
	}

	defer curres.Close(ctx)

	for curres.Next(ctx) {
		//Create a value into which the single document can be decoded
		var record l1common.AccountRecord
		err := curres.Decode(&record)
		if err != nil {
			log.Error(err)
			continue
		}
		res = append(res, record)
	}

	log.Info("The account data is: ", res)

	return res, nil
}

// retryDB retry will re-run the given function if failed till attempts. Between each attempt, sleep a while
func RetryDB(attempts int, sleep time.Duration, state, messageHash, status, userId string, todoCollection *mongo.Collection, fn func(string, string, string, string, *mongo.Collection) (interface{}, error)) (result interface{}, err error) {
	for i := 0; i < attempts; i++ {
		result, err := fn(state, messageHash, status, userId, todoCollection)
		if err != nil {
			log.Error("Retrying after error: ", err)
			time.Sleep(sleep)
			continue
		}
		log.WithFields(log.Fields{"result": result}).Info("Got result, will exit the retry")
		return result, nil
	}
	return nil, fmt.Errorf("retry failed after %d attempts, last error: %s", attempts, err)
}

// writeShare write a keyShare to mongoDB from a trusted MPC dealer
func WriteTx(tx common.BasicTx, txCollection *mongo.Collection) error {
	if txCollection.Name() != common.GloabalENVVars.MongoTxCollection {
		return fmt.Errorf("%s", errors.InsertingIntoWrongCollectionError)
	}
	return writeTx(tx, txCollection)
}

func WriteStakeTx(tx common.BasicTx, txCollection *mongo.Collection) error {
	if txCollection.Name() != common.GloabalENVVars.MongoStakeTxCollection {
		return fmt.Errorf("%s", errors.InsertingIntoWrongCollectionError)
	}
	return writeTx(tx, txCollection)
}

// readTx return target key share based on userid and token id
func ReadTx(txHash string, txCollection *mongo.Collection) (l1common.BasicTx, error) {
	var res l1common.BasicTx
	err := readTxByTxHash(txHash, txCollection).Decode(&res)
	if err != nil {
		return res, fmt.Errorf("failed to find tx with messageHash:%s, err: %v", txHash, err)
	}

	return res, nil
}

// readTx return target key share based on userid and token id
func ReadStakeTx(txHash string, txCollection *mongo.Collection) (l1common.StakeTx, error) {
	var res l1common.StakeTx
	err := readTxByTxHash(txHash, txCollection).Decode(&res)
	if err != nil {
		return res, fmt.Errorf("failed to find tx with messageHash:%s, err: %v", txHash, err)
	}

	return res, nil
}

// UpdateTx saves entire tx.
func UpdateTx(txHash string, tx l1common.BasicTx, txCollection *mongo.Collection) error {
	if txCollection.Name() != common.GloabalENVVars.MongoTxCollection {
		return errors.BuildAndLogErrorMsg(errors.InsertingIntoWrongCollectionError, nil)
	}
	return updateTx(txHash, tx, txCollection)
}

// UpdateStakeTx saves entire  stake tx.
func UpdateStakeTx(txHash string, tx l1common.BasicTx, txCollection *mongo.Collection) error {
	if txCollection.Name() != common.GloabalENVVars.MongoStakeTxCollection {
		return errors.BuildAndLogErrorMsg(errors.InsertingIntoWrongCollectionError, nil)
	}
	return updateTx(txHash, tx, txCollection)
}

// UpdateTxInputSignature updates only the transaction input fields in mongoDB
func UpdateTxInputSignature(txHash string, inputHash string, inputSignature string, todoCollection *mongo.Collection) error {
	ctx := context.Background()
	filter := bson.M{"txHash": txHash, "inputs.hash": inputHash}
	update := bson.M{"$set": bson.M{"inputs.$.signature": inputSignature}}

	_, err := todoCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.UpdateTxError, err)
	} else {
		log.Info("updated DB for: ", txHash)
	}

	return nil
}

func GetEtherumLastUsedNonce(ethNonceCollection *mongo.Collection, pubKeyHex string, nonce uint64) (l1common.EtherumAddressNonce, error) {
	ctx := context.Background()

	filter := bson.D{{"addresshex", pubKeyHex}}
	count, err := ethNonceCollection.CountDocuments(ctx, filter)
	var addressAndNonce l1common.EtherumAddressNonce
	if err != nil {
		return addressAndNonce, err
	} else if count == 0 {
		var doc l1common.EtherumAddressNonce
		doc.AddressHex = pubKeyHex
		_, err = ethNonceCollection.InsertOne(ctx, doc)
		if err != nil {
			return addressAndNonce, err
		}

	} else if count == 1 {
		err = ethNonceCollection.FindOne(ctx, filter).Decode(&addressAndNonce)
		if err != nil {
			return addressAndNonce, err
		}

		i := 0
		for ; i < len(addressAndNonce.LastNonces) && len(addressAndNonce.LastNonces) != 1; i++ {
			if addressAndNonce.LastNonces[i] >= nonce {
				log.Info("Need a larger Nonce than: ", nonce)
				break
			}
		}

		if i != 0 && len(addressAndNonce.LastNonces) >= 1 {
			//TODO This needs to checked its causing an error
			cleanUpNonces := addressAndNonce.LastNonces[i:len(addressAndNonce.LastNonces)]

			ethNonceCollection.UpdateOne(
				context.Background(),
				bson.D{{"addresshex", pubKeyHex}},
				bson.M{"$set": bson.M{"lastnonces": cleanUpNonces}})
		}
	} else {
		return addressAndNonce, fmt.Errorf("Lots of nonces. Something went wrong!!!")
	}
	return addressAndNonce, nil
}

func UpdateEtherumLastUsedNonce(ethNonceCollection *mongo.Collection, pubKeyHex string, nonce uint64) error {
	ctx := context.Background()

	filter := bson.D{{"addresshex", pubKeyHex}}
	count, err := ethNonceCollection.CountDocuments(ctx, filter)
	if err != nil || count != 1 || count == 0 { // Like a assertion
		return err
	}
	var addressAndNonce l1common.EtherumAddressNonce
	err = ethNonceCollection.FindOne(ctx, filter).Decode(&addressAndNonce)
	if err != nil {
		return err
	}
	addressAndNonce.LastNonces = append(addressAndNonce.LastNonces, nonce)

	update := bson.M{"$set": bson.M{"lastnonces": addressAndNonce.LastNonces}}
	_, err = ethNonceCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	} else {
		log.Info("updated nonce for ", pubKeyHex)
	}
	return nil
}

func GetBitcoinUsedUtxos(btcUtxosCollection *mongo.Collection, btcAddress string) (map[string]bool, error) {
	ctx := context.Background()

	var addressUTXOs l1common.BitcoinAddressUTXO
	filter := bson.D{{"address", btcAddress}}
	count, err := btcUtxosCollection.CountDocuments(ctx, filter)
	if err != nil { // Like a assertion
		log.Fatal(errors.DBConnectionError, err)
	} else if count == 0 {
		var doc l1common.BitcoinAddressUTXO
		doc.Address = btcAddress
		doc.UsedUTXOS = make(map[string]bool)

		_, err = btcUtxosCollection.InsertOne(ctx, doc)
		if err != nil {
			return doc.UsedUTXOS, err
		}
	} else if count == 1 {
		err = btcUtxosCollection.FindOne(ctx, filter).Decode(&addressUTXOs)
		if err != nil {
			return map[string]bool{}, err
		}
	} else {
		return map[string]bool{}, fmt.Errorf("UTXOs maped on multiple addresses.")
	}

	return addressUTXOs.UsedUTXOS, nil
}

func UpdateBITCoinUsedUTXOs(btcUtxosCollection *mongo.Collection, btcAddress string, spentUTXOs []string, isReverting bool) error {
	log.Info("Entering UpdateBITCoinUsedUTXOs address: ", btcAddress)

	ctx := context.Background()
	filter := bson.D{{"address", btcAddress}}

	count, err := btcUtxosCollection.CountDocuments(ctx, filter)
	if err != nil {
		return fmt.Errorf("%v", err)
	} else if count == 1 {
		var addressUTXOs l1common.BitcoinAddressUTXO
		err = btcUtxosCollection.FindOne(ctx, filter).Decode(&addressUTXOs)
		if err != nil {
			return errors.BuildAndLogErrorMsgWithData(errors.UTXONotFoundError, err, btcAddress)
		}
		log.Info("UTXOS found for: ", btcAddress, " utxos:", addressUTXOs)

		if isReverting {
			for _, utxo := range spentUTXOs {
				log.Info("Reverting utxo record for: ", utxo)
				delete(addressUTXOs.UsedUTXOS, utxo)
			}
		} else {
			for _, utxo := range spentUTXOs {
				log.Info("Adding utxo record for: ", utxo)
				addressUTXOs.UsedUTXOS[utxo] = true
			}
		}
		log.Info("Update UTXO set", addressUTXOs.UsedUTXOS)

		update := bson.M{"$set": bson.M{"usedutxos": addressUTXOs.UsedUTXOS}}
		_, err = btcUtxosCollection.UpdateOne(ctx, filter, update)
		if err != nil {
			return err
		} else {
			log.Info("updated utxos for ", btcAddress)
		}

	} else {
		return errors.BuildAndLogErrorMsg(errors.MultipleMapedUTXOsError, err)
	}

	return nil
}

func GetNEARPendingNonce(nearNonceCollection *mongo.Collection, address string) (l1common.NEARAccountNonce, error) {
	ctx := context.Background()

	filter := bson.D{{"address", address}}
	var accountNonce l1common.NEARAccountNonce

	count, err := nearNonceCollection.CountDocuments(ctx, filter)
	if err != nil {
		return accountNonce, err
	} else if count == 0 {
		accountNonce.Address = address
		_, err = nearNonceCollection.InsertOne(ctx, accountNonce)
		if err != nil {
			return accountNonce, err
		}
	} else if count == 1 {
		err = nearNonceCollection.FindOne(ctx, filter).Decode(&accountNonce)
		if err != nil {
			return accountNonce, err
		}
	} else {
		return accountNonce, fmt.Errorf("Lots of nonces. Something went wrong!!!")
	}
	return accountNonce, nil
}

func UpdateNEARNextPendingNonce(nearNonceCollection *mongo.Collection, address string, nonce uint64) error {
	ctx := context.Background()

	filter := bson.D{{"address", address}}
	count, err := nearNonceCollection.CountDocuments(ctx, filter)
	if err != nil || count != 1 || count == 0 { // Like a assertion
		return err
	}
	var addressAndNonce l1common.NEARAccountNonce
	err = nearNonceCollection.FindOne(ctx, filter).Decode(&addressAndNonce)
	if err != nil {
		return err
	}
	addressAndNonce.Nonce = nonce

	update := bson.M{"$set": bson.M{"nonce": addressAndNonce.Nonce}}
	_, err = nearNonceCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	} else {
		log.Info("updated nonce for ", address)
	}
	return nil
}

func writeTx(dataEntry interface{}, txCollection *mongo.Collection) error {
	ctx := context.Background()
	_, err := txCollection.InsertOne(ctx, dataEntry)
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.AddingTxIntoDBError, err)
	}
	return nil
}

func readTxByTxHash(txHash string, txCollection *mongo.Collection) *mongo.SingleResult {
	filter := bson.D{{"txHash", txHash}}
	ctx := context.Background()
	return txCollection.FindOne(ctx, filter) //.Decode(&res)
}

func updateTx(txHash string, tx interface{}, todoCollection *mongo.Collection) error {
	ctx := context.Background()
	filter := bson.D{{"txHash", txHash}}
	update := bson.M{"$set": tx}
	_, err := todoCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return errors.BuildAndLogErrorMsg(errors.UpdateTxError, err)
	} else {
		log.Info("updated DB for: ", txHash)
	}

	return nil
}
