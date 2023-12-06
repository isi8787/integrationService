package blockchains

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"finco/l1integration/common"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"
	"fmt"
	"strconv"

	cardano "github.com/1artashes97/cardano-go"
	blockfrost "github.com/blockfrost/blockfrost-go"
)

var CardanoMainNet = ""
var CardanoTestNet = "https://cardano-preview.blockfrost.io/api/v0"
var BlockfrostAccessKey = "previewgzv0ay2LqRAtsGqNCnhw1RCgZMZDbMBU"

func getCardanoUtxos(addr cardano.Address) ([]cardano.UTxO, error) {
	bfApiClinet := blockfrost.NewAPIClient(
		blockfrost.APIClientOptions{
			Server:    CardanoTestNet,
			ProjectID: BlockfrostAccessKey,
		},
	)
	butxos, err := bfApiClinet.AddressUTXOs(context.Background(), addr.Bech32(), blockfrost.APIQueryParams{})
	if err != nil {
		// Addresses without UTXOs return NotFound error
		if err, ok := err.(*blockfrost.APIError); ok {
			if _, ok := err.Response.(blockfrost.NotFound); ok {
				return []cardano.UTxO{}, nil
			}
		}
		return nil, err
	}

	utxos := make([]cardano.UTxO, len(butxos))

	for i, butxo := range butxos {
		txHash, err := cardano.NewHash32(butxo.TxHash)
		if err != nil {
			return nil, err
		}

		amount := cardano.NewValue(0)
		for _, a := range butxo.Amount {
			if a.Unit == "lovelace" {
				lovelace, err := strconv.ParseUint(a.Quantity, 10, 64)
				if err != nil {
					return nil, err
				}
				amount.Coin += cardano.Coin(lovelace)
			} else {
				unitBytes, err := hex.DecodeString(a.Unit)
				if err != nil {
					return nil, err
				}
				policyID := cardano.NewPolicyIDFromHash(unitBytes[:28])
				assetName := string(unitBytes[28:])
				assetValue, err := strconv.ParseUint(a.Quantity, 10, 64)
				if err != nil {
					return nil, err
				}
				currentAssets := amount.MultiAsset.Get(policyID)
				if currentAssets != nil {
					currentAssets.Set(
						cardano.NewAssetName(assetName),
						cardano.BigNum(assetValue),
					)
				} else {
					amount.MultiAsset.Set(
						policyID,
						cardano.NewAssets().
							Set(
								cardano.NewAssetName(string(assetName)),
								cardano.BigNum(assetValue),
							),
					)
				}
			}
		}

		utxos[i] = cardano.UTxO{
			Spender: addr,
			TxHash:  txHash,
			Amount:  amount,
			Index:   uint64(butxo.OutputIndex),
		}
	}

	return utxos, nil
}

func submitCardanoTx(tx *cardano.Tx) (string, error) {
	bfApiClinet := blockfrost.NewAPIClient(
		blockfrost.APIClientOptions{
			Server:    CardanoTestNet,
			ProjectID: BlockfrostAccessKey,
		},
	)
	txBytes := tx.Bytes()
	fmt.Printf("Signed transaction : %v", tx)

	txHash, err := bfApiClinet.TransactionSubmit(context.Background(), txBytes)
	if err != nil {
		return "", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}
	return txHash, nil
}

func getLatestSlotNumber() (uint64, error) {
	bfApiClinet := blockfrost.NewAPIClient(
		blockfrost.APIClientOptions{
			Server:    "https://cardano-preview.blockfrost.io/api/v0",
			ProjectID: "previewgzv0ay2LqRAtsGqNCnhw1RCgZMZDbMBU",
		},
	)

	block, err := bfApiClinet.BlockLatest(context.Background())
	if err != nil {
		return 0, errors.BuildAndLogErrorMsg(errors.BlockFrostGatewayError, err)
	}

	return uint64(block.Slot + 100), nil
}

func ChangeCardanoUTXOState(tx cardano.Tx, cardanoAddress string, isReverting bool) error {
	utxos := make([]string, len(tx.Body.Inputs))
	for i, utxo := range tx.Body.Inputs {
		utxos[i] = utxo.TxHash.String()
	}
	return gateways.UpdateBITCoinUsedUTXOs(gateways.DB.Cardano, cardanoAddress, utxos, isReverting)
}

func CreateCardanoTx(tx common.BasicTx, fromAddress string) (common.BasicTx, error) {
	txBuilder := cardano.NewTxBuilder(&cardano.ProtocolParams{})

	tx.FromAddress = fromAddress
	senderAddress, err := cardano.NewAddress(tx.FromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	tx.Amount, err = strconv.ParseFloat(tx.Value, 64)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	receiverAddress, err := cardano.NewAddress(tx.ToAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	senderUtxos, err := getCardanoUtxos(senderAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.BalanceError, err)
	}

	// same utxo mechanism with bitcoin
	usedUtxos, err := gateways.GetBitcoinUsedUtxos(gateways.DB.Cardano, tx.FromAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UTXONotFoundError, err)
	}

	// in this functions amount passes by referance we ned to recreate this amount as variable
	txBuilder.AddOutputs(cardano.NewTxOutput(receiverAddress, cardano.NewValue(cardano.Coin(tx.Amount*1000000))))

	// recreating amount variable for future modifications
	amountWhithFee := cardano.NewValue(cardano.Coin(tx.Amount * 1000000)).Add(cardano.NewValue(1000000))
	fee := cardano.NewValue(1000000)
	//var index uint = 0
	haveRequiredAmount := false
	for _, utxo := range senderUtxos {
		if usedUtxos[utxo.TxHash.String()] {
			continue
		}
		amountCompareResult := amountWhithFee.Cmp(utxo.Amount)
		if amountCompareResult == -1 {

			newInput := cardano.NewTxInput(utxo.TxHash, uint(utxo.Index), utxo.Amount)
			newOutputToMe := cardano.NewTxOutput(senderAddress, utxo.Amount.Sub(amountWhithFee))
			txBuilder.AddInputs(newInput)
			txBuilder.AddOutputs(newOutputToMe)

			haveRequiredAmount = true
			break
		} else if amountCompareResult == 0 {
			fmt.Println("amountCompareResult: 0")
			newInput := cardano.NewTxInput(utxo.TxHash, uint(utxo.Index), utxo.Amount)
			txBuilder.AddInputs(newInput)
			haveRequiredAmount = true
			break
		} else if amountCompareResult == 1 {
			fmt.Println("amountCompareResult: 1")
			newInput := cardano.NewTxInput(utxo.TxHash, uint(utxo.Index), utxo.Amount)
			txBuilder.AddInputs(newInput)
			amountWhithFee = amountWhithFee.Sub(utxo.Amount)
			//index++
		} else {
			continue
		}
	}

	if !haveRequiredAmount {
		return tx, errors.BuildAndLogErrorMsg(errors.NotEnoughAmountError, nil)
	}

	slotNo, err := getLatestSlotNumber()
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}
	txBuilder.SetTTL(slotNo)
	// TODO: Calculate minimal fee to set. Now every tx fee is 1 ADA
	txBuilder.SetFee(fee.Coin)

	cardanoTx, err := txBuilder.BuildWithoutSigning()
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}

	serialized, err := json.Marshal(cardanoTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	txHash, err := cardanoTx.Hash()
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.TxBuildError, err)
	}
	txHashByteArray := make([]byte, 32)
	copy(txHashByteArray, txHash)

	tx.TxHash = hex.EncodeToString(txHashByteArray)
	tx.FullTx = string(serialized)
	tx.Status = common.TxCreated
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: tx.TxHash, InputIndex: 0}}
	gateways.WriteTx(tx, gateways.DB.Transactions)

	return tx, nil
}

func CompleteCardanoTx(tx common.BasicTx, witness []cardano.VKeyWitness) (string, error) {
	var err error

	var cardanoTx cardano.Tx
	err = json.Unmarshal([]byte(tx.FullTx), &cardanoTx)
	if err != nil {
		return "", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	cardanoTx.ConfigureWitnessSet(witness)

	err = ChangeCardanoUTXOState(cardanoTx, tx.FromAddress, false)
	if err != nil {
		return "", errors.BuildAndLogErrorMsg(errors.UTXOUpdateError, err)
	}

	txHash, err := submitCardanoTx(&cardanoTx)
	if err != nil {
		ChangeCardanoUTXOState(cardanoTx, tx.FromAddress, true)
		return "", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)
	}
	tx.Receipt = txHash
	tx.Status = common.TxSubmitted

	gateways.WriteTx(tx, gateways.DB.Transactions)

	return txHash, err
}
