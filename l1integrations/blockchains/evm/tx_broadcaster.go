package evm

import (
	"context"
	"encoding/json"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"go.mongodb.org/mongo-driver/mongo"
)

type EVMTxBroadcaster struct {
	ChianID  *big.Int
	gateways evmGateways
}

func NewEVMTxBroadcaster(chainID *big.Int, nodeUrl string, nonceCollection *mongo.Collection, txsCollection *mongo.Collection) (*EVMTxBroadcaster, error) {
	evm := EVMTxBroadcaster{
		ChianID: chainID,
	}

	eg, err := NewEvmGateways(nodeUrl, nonceCollection, txsCollection)
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}
	evm.gateways = eg

	return &evm, nil
}

func (evm *EVMTxBroadcaster) CompleteTxHelper(FullTx string, signature l1common.EcdsaSignature) ([]byte, *types.Transaction, error) {
	tx, err := unmarshalFromJson([]byte(FullTx))
	if err != nil {
		return nil, nil, errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}

	signedTx, err := evm.setSignatures(tx, signature)
	if err != nil {
		return nil, nil, errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}

	serializedSignedTx, err := evm.commitTx(signedTx)
	if err != nil {
		return nil, nil, errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}

	return serializedSignedTx, signedTx, nil
}

func (evm *EVMTxBroadcaster) CompleteTx(txHash string, signature l1common.EcdsaSignature) (*types.Transaction, error) {
	basicTx, err := readBasicTxFromDB(txHash, evm.gateways.TXsCollection)
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}

	if basicTx.ApproveFullTx != "" && len(basicTx.Inputs) == 2 {
		var approveSignature l1common.EcdsaSignature
		err := json.Unmarshal([]byte(basicTx.Inputs[1].Signature), &approveSignature)
		_, _, err = evm.CompleteTxHelper(basicTx.ApproveFullTx, approveSignature)
		if err != nil {
			return nil, errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
		}
	}

	serializedSignedTx, signedTx, err := evm.CompleteTxHelper(basicTx.FullTx, signature)
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}

	signatureJSON, _ := json.Marshal(signature)
	basicTx.FullTx = string(serializedSignedTx)
	basicTx.Inputs[0].Signature = string(signatureJSON)
	basicTx.Status = l1common.TxSubmitted

	err = updateBasicTxInDB(txHash, basicTx, evm.gateways.TXsCollection)
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}

	return signedTx, nil
}

func (evm *EVMTxBroadcaster) setSignatures(unsigned types.Transaction, signature l1common.EcdsaSignature) (*types.Transaction, error) {
	sigbytes := append(signature.R.Bytes(), signature.S.Bytes()...)

	if signature.V > 0 {
		sigbytes = append(sigbytes, big.NewInt(int64(signature.V)).Bytes()...)
	} else if signature.V == 0 {
		empty := []byte{0}
		sigbytes = append(sigbytes, empty[0])
	}

	signereth := types.NewEIP155Signer(evm.ChianID)
	signedTx, err := unsigned.WithSignature(signereth, sigbytes)
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.SignatureError, err)
	}

	return signedTx, nil
}

func (evm *EVMTxBroadcaster) commitTx(signedTx *types.Transaction) ([]byte, error) {
	err := evm.gateways.Client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	signedTxJSON, err := json.Marshal(*signedTx)
	if err != nil {
		return nil, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	return signedTxJSON, nil
}
