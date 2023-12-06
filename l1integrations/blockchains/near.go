package blockchains

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"finco/l1integration/blockchains/near"
	"finco/l1integration/common"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"
	"fmt"
	"math/big"
	"strconv"

	"github.com/mr-tron/base58"
	"github.com/near/borsh-go"
	log "github.com/sirupsen/logrus"
	nearkeys "github.com/textileio/near-api-go/keys"
	neartx "github.com/textileio/near-api-go/transaction"
)

func CreateNEARTx(tx common.BasicTx, pk []byte) (common.BasicTx, error) {
	dataArr := [32]byte{}
	copy(dataArr[:], pk)

	val, _ := strconv.ParseInt(tx.Value, 10, 64)
	var halfYocto big.Int = *big.NewInt(int64(1000000000000)) // must mul 2 times
	var yocto big.Int
	yocto.Mul(&halfYocto, &halfYocto)
	var deposit big.Int
	deposit.Mul(big.NewInt(val), &yocto)

	pubKey := nearkeys.PublicKey{
		Type: nearkeys.ED25519,
		Data: pk,
	}

	txKey := neartx.PublicKey{
		KeyType: uint8(pubKey.Type),
	}

	pkeyStr, _ := pubKey.ToString()
	fromAddress := hex.EncodeToString(pk)
	accountState, err := near.GetAccountStateOf(fromAddress, pkeyStr)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.GetPendingNocceError, err)
	}

	blockHash, err := base58.Decode(accountState.BlockHash)
	if err != nil {
		return tx, fmt.Errorf("Error : %v\n", err)
	}
	var blockHashArr [32]byte
	copy(blockHashArr[:], blockHash)

	currentNonce := accountState.Nonce
	nonceFromLocalDb, err := gateways.GetNEARPendingNonce(gateways.DB.NEARProtocol, tx.FromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.GetPendingNocceError, err)
	}

	if currentNonce < nonceFromLocalDb.Nonce {
		currentNonce = nonceFromLocalDb.Nonce
	}

	copy(txKey.Data[:], pubKey.Data)
	nearTx := neartx.Transaction{
		SignerID:   fromAddress,
		PublicKey:  txKey,
		Nonce:      currentNonce + 1,
		ReceiverID: tx.ToAddress,
		BlockHash:  blockHashArr,
		Actions:    []neartx.Action{neartx.TransferAction(deposit)},
	}

	hash, _, err := near.GetHashOfNEARTx(nearTx)
	if err != nil {
		fmt.Printf("%v", err)
		return tx, err
	}

	fullTxJSON, err := json.Marshal(nearTx)
	if err != nil {
		fmt.Printf("%v", err)
	}
	hexHash := hex.EncodeToString(hash[:])

	tx.FromAddress = fromAddress
	//tx.Fee = float64(minFee)
	tx.TxHash = hexHash
	tx.FullTx = string(fullTxJSON)
	tx.Status = l1common.TxCreated
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: hexHash, InputIndex: 0}}

	log.Info("NEAR Transaction", string(fullTxJSON))

	err = gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil
}

func CompleteNEARTx(tx common.BasicTx, signature string) (string, error) {

	var completeTx neartx.Transaction
	err := json.Unmarshal([]byte(tx.FullTx), &completeTx)
	if err != nil {
		return "", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	fullsig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return "", errors.BuildAndLogErrorMsg(errors.Base64DecodeError, err)
	}

	var sig [64]byte
	copy(sig[:], fullsig)
	signedTx := neartx.SignedTransaction{
		Transaction: completeTx,
		Signature: neartx.Signature{
			KeyType: completeTx.PublicKey.KeyType,
			Data:    sig,
		},
	}

	bytes, err := borsh.Serialize(signedTx)
	if err != nil {
		return "", errors.BuildAndLogErrorMsg(errors.TxSerializeError, err)
	}

	res, err := near.RPCCall(near.TXCommitMethod, []string{base64.StdEncoding.EncodeToString(bytes)})
	if err != nil {
		return "", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}
	fmt.Printf("%v", res)
	serializedReceipt, _ := json.Marshal(res.Result)

	var txReceiptRes near.TransactionReceiptResult
	json.Unmarshal(serializedReceipt, &txReceiptRes)

	gateways.UpdateNEARNextPendingNonce(gateways.DB.NEARProtocol, tx.FromAddress, uint64(txReceiptRes.Transaction.Nonce+1))

	serializedCompleteTx, _ := json.Marshal(signedTx)
	tx.FullTx = string(serializedCompleteTx)
	tx.Status = common.TxSubmitted

	gateways.WriteTx(tx, gateways.DB.Transactions)

	return txReceiptRes.Transaction.Hash, nil
}
