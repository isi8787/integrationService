package operations

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"finco/l1integration/blockchains"
	"finco/l1integration/blockchains/evm"
	"finco/l1integration/common"
	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"
	"fmt"
	"math/big"
	"net/http"
	"strconv"

	"bitbucket.org/carsonliving/cryptographymodules/kryptology/pkg/core/curves"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	log "github.com/sirupsen/logrus"

	"github.com/1artashes97/cardano-go"
)

//TODO: all api functions need minimum regex validation for inputs

var ethClient *ethclient.Client = gateways.InfuraETHClient()

// PostTx prepare transaction requiring an ECDSA signature
func PostTx(c *gin.Context) {
	var tx l1common.BasicTx
	var err error

	c.ShouldBindBodyWith(&tx, binding.JSON)

	if l1common.BlockchainsMap[tx.BlockchainId] == l1common.ECDSA {

		share, err := gateways.ReadECDSAShare(tx.UserId, tx.BlockchainId, tx.AccountName, gateways.DB.KeyShares)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadMPCShareError, err)), c.Writer)
			return
		}

		pubKey, err := getPublicKey(share)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.GetPublicKeyError, err)), c.Writer)
			return
		}
		tx.FromAddress = crypto.PubkeyToAddress(pubKey).String()
		switch op := tx.BlockchainId; op {
		case blockchains.Ethereum:
			contractSymbol := tx.OriginChain
			if tx.TokenId == blockchains.Ethereum {
				tx, err = blockchains.ETHTx(tx, pubKey)
			} else if contractSymbol == "UNISWAP-internal" {
				tx, err = blockchains.EthereumUniSwapTx(tx, pubKey)
			} else if contractSymbol == "1INCHSWAP-internal" {
				tx, err = blockchains.EthereumOneInchSwapTx(tx, pubKey)
			} else {
				tx, err = blockchains.ERC20Tx(tx, pubKey)
			}
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
				return
			}
		case blockchains.Bitcoin:
			tx, err = blockchains.BTCTx(tx, pubKey)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
				return
			}
		case blockchains.Avalanche:
			targetChain := tx.OriginChain
			switch avaxChain := targetChain; avaxChain {
			case blockchains.AvalancheXChain, blockchains.AvalanchePChain:
				tx, err = blockchains.SendAVMChainAvax(tx, pubKey, avaxChain)
			default:
				tx, err = blockchains.AVAXTx(tx, pubKey)
			}
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
				return
			}
		case blockchains.BSC:
			contractSymbol := tx.OriginChain
			if tx.TokenId == blockchains.BSC {
				tx, err = blockchains.BNBTx(tx, pubKey)
			} else if contractSymbol == "UNISWAP-internal" {
				tx, err = blockchains.BinanceUniSwapTx(tx, pubKey)
			} else if contractSymbol == "1INCHSWAP-internal" {
				tx, err = blockchains.BinanceOneInchSwapTx(tx, pubKey)
			} else {
				tx, err = blockchains.BEP20Tx(tx, pubKey)
			}
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
				return
			}
		case blockchains.Polygon:
			contractSymbol := tx.OriginChain
			if tx.TokenId == blockchains.Polygon {
				tx, err = blockchains.PolygonTx(tx, pubKey)
			} else if contractSymbol == "UNISWAP-internal" {
				tx, err = blockchains.PolygonUniSwapTx(tx, pubKey)
			} else if contractSymbol == "1INCHSWAP-internal" {
				tx, err = blockchains.PolygonUniSwapTx(tx, pubKey)
			}
			// else {
			// 	tx, err = blockchains.BEP20Tx(tx, pubKey)
			// }

			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
				return
			}
		}
	} else if l1common.BlockchainsMap[tx.BlockchainId] == common.EDDSA {
		share, err := gateways.ReadEDDSAShare(tx.UserId, tx.BlockchainId, tx.AccountName, gateways.DB.KeyShares)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.ReadMPCShareError, err)), c.Writer)
			return
		}

		pkRawDecodedBytes, err := base64.StdEncoding.DecodeString(share.PK)
		if err != nil {
			log.Error(err)
		}

		switch op := tx.BlockchainId; op {
		case blockchains.Algorand:
			tx, err = blockchains.ALGOTx(tx, pkRawDecodedBytes)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
				return
			}

		case blockchains.NEARProtocol:
			tx, err = blockchains.CreateNEARTx(tx, pkRawDecodedBytes) // TODO: Test
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
				return
			}
		case blockchains.Cardano:
			tx, err = blockchains.CreateCardanoTx(tx, share.Address)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
				return
			}
		}
	}

	common.ValidateAndWriteResponse(tx, err, c.Writer)
	return
}

// RemoteTx prepare transaction requiring an ECDSA signature from a remote source
func RemoteTx(c *gin.Context) {
	var tx l1common.BasicTx
	var err error
	c.ShouldBindBodyWith(&tx, binding.JSON)

	if l1common.BlockchainsMap[tx.BlockchainId] == l1common.ECDSA {

		share, err := gateways.ReadECDSAShare(tx.UserId, tx.BlockchainId, tx.AccountName, gateways.DB.KeyShares)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadMPCShareError, err)), c.Writer)
			return
		}

		pubKey, err := getPublicKey(share)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.GetPublicKeyError, err)), c.Writer)
			return
		}

		switch op := tx.BlockchainId; op {
		case blockchains.Ethereum:
			if tx.TokenId == blockchains.Ethereum {
				tx, err = blockchains.ETHWCProcess(tx, pubKey)
			}
		}

	}

	common.ValidateAndWriteResponse(tx, err, c.Writer)
	return
}

// PostTx prepare transaction requiring an ECDSA signature
func CrossChainTx(c *gin.Context) {
	var tx l1common.BasicTx
	c.ShouldBindBodyWith(&tx, binding.JSON)

	txio := c.Request.URL.Query().Get("txio")

	var err error
	if l1common.BlockchainsMap[tx.BlockchainId] == common.ECDSA {

		share, err := gateways.ReadECDSAShare(tx.UserId, tx.BlockchainId, tx.AccountName, gateways.DB.KeyShares)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadMPCShareError, err)), c.Writer)
			return
		}

		pubKey, err := getPublicKey(share)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.GetPublicKeyError, err)), c.Writer)
			return
		}

		switch op := tx.BlockchainId; op {
		case blockchains.Avalanche:
			targetChain := tx.ToAddress[0:1]
			originChain := tx.OriginChain
			if txio == blockchains.AvalancheExport {
				tx, err = blockchains.CrossChainAvaxExport(tx, pubKey, originChain, targetChain)
			} else if txio == blockchains.AvalancheImport {
				tx, err = blockchains.CrossChainAvaxImport(tx, pubKey, originChain, targetChain)
			}
		}
	}

	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
		return
	}

	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
		return
	}

	common.ValidateAndWriteResponse(tx, err, c.Writer)
	return
}

// StakeTx prepare transaction requiring an ECDSA signature
func StakeTx(c *gin.Context) {
	var tx l1common.BasicTx
	c.ShouldBindBodyWith(&tx, binding.JSON)

	var err error
	if l1common.BlockchainsMap[tx.BlockchainId] == common.ECDSA {

		share, err := gateways.ReadECDSAShare(tx.UserId, tx.BlockchainId, tx.AccountName, gateways.DB.KeyShares)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadMPCShareError, err)), c.Writer)
			return
		}

		pubKey, err := getPublicKey(share)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.GetPublicKeyError, err)), c.Writer)
			return
		}

		switch op := tx.BlockchainId; op {
		case blockchains.Ethereum:
			if tx.TokenId == blockchains.Ethereum {
				tx, err = blockchains.ETH2Deposit(tx, pubKey)
			}

		case blockchains.Avalanche:
			tx, err = blockchains.AvaxStake(tx, pubKey)
		}

	}

	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.TxBuildError, err)), c.Writer)
		return
	}

	common.ValidateAndWriteResponse(tx, err, c.Writer)
	return
}

// CompleteTx process signature for a transaction requiring ECDSA type signature
func CompleteTx(c *gin.Context) {
	var txInputs l1common.TxSignedInputs
	c.ShouldBindBodyWith(&txInputs, binding.JSON)

	messageHash := txInputs.Inputs[0].Hash

	idHash := c.Request.URL.Query().Get("idHash")
	if idHash == "" {
		idHash = messageHash
	}

	tx, err := gateways.ReadTx(idHash, gateways.DB.Transactions)
	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadTxError, err)), c.Writer)
		return
	}

	if tx.Status != l1common.TxCreated {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
		return
	}

	if len(tx.Inputs) != len(txInputs.Inputs) {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.IncorrectInputs, err)), c.Writer)
		return
	}

	if l1common.BlockchainsMap[tx.BlockchainId] == common.ECDSA {
		sigNum := 0
		for _, txInput := range txInputs.Inputs {
			var signature l1common.EcdsaSignature
			err := json.Unmarshal([]byte(txInput.Signature), &signature)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)), c.Writer)
				return
			}

			signatureJSON, err := json.Marshal(signature)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.MarshallError, err)), c.Writer)
				return
			}

			err = gateways.UpdateTxInputSignature(idHash, messageHash, string(signatureJSON), gateways.DB.Transactions)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.WriteTxError, err)), c.Writer)
				return
			}

			for i, val := range tx.Inputs {
				if val.Hash == messageHash {
					tx.Inputs[i].Signature = string(signatureJSON)
					sigNum++
				} else {
					if val.Signature != "" {
						sigNum++
					}
				}
			}
		}

		if len(tx.Inputs) == sigNum {
			share, err := gateways.ReadECDSAShare(tx.UserId, tx.BlockchainId, tx.AccountName, gateways.DB.KeyShares)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadMPCShareError, err)), c.Writer)
				return
			}

			pubKey, err := getPublicKey(share)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.GetPublicKeyError, err)), c.Writer)
				return
			}

			var txReceipt string
			switch op := tx.BlockchainId; op {
			case blockchains.Ethereum:
				var fullSignature l1common.EcdsaSignature
				err := json.Unmarshal([]byte(tx.Inputs[0].Signature), &fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)), c.Writer)
					return
				}

				fullTx, err := blockchains.CompleteETHTx(messageHash, fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
					return
				}

				err = gateways.UpdateEtherumLastUsedNonce(gateways.DB.Ethereum, tx.FromAddress, fullTx.Nonce())
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.NonceUpdateError, err)), c.Writer)
					return
				}

				txReceipt = fullTx.Hash().Hex()
			case blockchains.Avalanche:
				var fullSignature l1common.EcdsaSignature
				err := json.Unmarshal([]byte(tx.Inputs[0].Signature), &fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)), c.Writer)
					return
				}

				targetChain := tx.ToAddress[0:1]
				switch avaxChain := targetChain; avaxChain {
				case blockchains.AvalancheXChain, blockchains.AvalanchePChain:
					fullTx, err := blockchains.CompleteAvaxAVMTx(messageHash, fullSignature, targetChain)
					if err != nil {
						common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
						return
					}
					txReceipt = fullTx.FullTx
				default:
					fullTx, err := blockchains.CompleteAvaxTx(messageHash, fullSignature)
					if err != nil {
						common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
						return
					}
					txReceipt = fullTx.Hash().Hex()
				}
			case blockchains.Bitcoin:
				txReceipt, err = blockchains.SendBTCModified(idHash, tx.Inputs, pubKey, gateways.BD)
				if err != nil {
					// TODO : revert used utxos in utxo db.
					// gateways.UpdateBITCoinUsedUTXOs(gateways.DB.Bitcoin, tx.FromAddress, preparedUTXOs, true)
					// ---
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
					return
				}

				var preparedUTXOs []string = make([]string, len(tx.Inputs))
				for i, input := range tx.Inputs {
					preparedUTXOs[i] = input.Hash
				}
				err = gateways.UpdateBITCoinUsedUTXOs(gateways.DB.Bitcoin, tx.FromAddress, preparedUTXOs, false)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UTXOUpdateError, err)), c.Writer)
					return
				}

			case blockchains.BSC:
				var fullSignature l1common.EcdsaSignature
				err := json.Unmarshal([]byte(tx.Inputs[0].Signature), &fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)), c.Writer)
					return
				}

				fullTx, err := blockchains.CompleteBNBTx(messageHash, fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
					return
				}

				err = gateways.UpdateEtherumLastUsedNonce(gateways.DB.BSC, tx.FromAddress, fullTx.Nonce())
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.NonceUpdateError, err)), c.Writer)
					return
				}

				txReceipt = fullTx.Hash().Hex()

			case blockchains.Polygon:
				var fullSignature l1common.EcdsaSignature
				err := json.Unmarshal([]byte(tx.Inputs[0].Signature), &fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)), c.Writer)
					return
				}

				fullTx, err := blockchains.CompletePolygonTx(messageHash, fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
					return
				}

				err = gateways.UpdateEtherumLastUsedNonce(gateways.DB.Polygon, tx.FromAddress, fullTx.Nonce())
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.NonceUpdateError, err)), c.Writer)
					return
				}

				txReceipt = fullTx.Hash().Hex()
			}
			tx.Receipt = txReceipt
			common.ValidateAndWriteResponse(tx, err, c.Writer)
			return
		} else {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.InputsError, err)), c.Writer)
			return
		}

	} else if l1common.BlockchainsMap[tx.BlockchainId] == common.EDDSA {
		txInput := txInputs.Inputs[0]
		err = gateways.UpdateTxInputSignature(idHash, messageHash, txInput.Signature, gateways.DB.Transactions)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.WriteTxError, err)), c.Writer)
			return
		}

		var txID string
		switch op := tx.BlockchainId; op {
		case blockchains.Algorand:
			txID, err = blockchains.CompleteALGOTx(tx, txInput.Signature)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
				return
			}

		case blockchains.NEARProtocol:
			txID, err = blockchains.CompleteNEARTx(tx, txInput.Signature)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
				return
			}

		case blockchains.Cardano:

			share, err := gateways.ReadEDDSAShare(tx.UserId, tx.BlockchainId, tx.AccountName, gateways.DB.KeyShares)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("Error: %s", errors.BuildAndLogErrorMsg(errors.ReadMPCShareError, err)), c.Writer)
				return
			}

			pkRawDecodedBytes, err := base64.StdEncoding.DecodeString(share.PK)
			if err != nil {
				log.Error(err)
			}

			signatureRawDecodedBytes, err := base64.StdEncoding.DecodeString(txInput.Signature)
			if err != nil {
				log.Error(err)
			}

			witnesses := []cardano.VKeyWitness{cardano.VKeyWitness{
				VKey:      pkRawDecodedBytes,
				Signature: signatureRawDecodedBytes,
			}}

			txID, err = blockchains.CompleteCardanoTx(tx, witnesses)

			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
				return
			}
		}
		tx.Receipt = txID
		common.ValidateAndWriteResponse(tx, err, c.Writer)
		return
	}

	common.ValidateAndWriteResponse(tx, err, c.Writer)
	return
}

// CompleteCrossChainTx process signature for a transaction for doing cross chain operation
func CompleteCrossChainTx(c *gin.Context) {
	var txInput l1common.TxInputs
	c.ShouldBindBodyWith(&txInput, binding.JSON)

	messageHash := txInput.Hash

	idHash := c.Request.URL.Query().Get("idHash")
	if idHash == "" {
		idHash = messageHash
	}

	txio := c.Request.URL.Query().Get("txio")
	tx, err := gateways.ReadTx(idHash, gateways.DB.Transactions)
	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadTxError, err)), c.Writer)
		return
	}

	if l1common.BlockchainsMap[tx.BlockchainId] == common.ECDSA {

		var signature l1common.EcdsaSignature
		err := json.Unmarshal([]byte(txInput.Signature), &signature)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)), c.Writer)
			return
		}
		signatureJSON, err := json.Marshal(signature)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.MarshallError, err)), c.Writer)
			return
		}

		err = gateways.UpdateTxInputSignature(idHash, messageHash, string(signatureJSON), gateways.DB.Transactions)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.WriteTxError, err)), c.Writer)
			return
		}

		sigNum := 0
		for i, val := range tx.Inputs {
			if val.Hash == messageHash {
				tx.Inputs[i].Signature = string(signatureJSON)
				sigNum++
			} else {
				if val.Signature != "" {
					sigNum++
				}
			}
		}

		if len(tx.Inputs) == sigNum {
			var txReceipt string
			switch op := tx.BlockchainId; op {
			case blockchains.Avalanche:
				var fullSignature l1common.EcdsaSignature
				err := json.Unmarshal([]byte(tx.Inputs[0].Signature), &fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)), c.Writer)
					return
				}

				targetChain := tx.ToAddress[0:1]
				originChain := tx.OriginChain
				fullTx, err := blockchains.CompleteAvaxCrossChainTx(messageHash, fullSignature, originChain, targetChain, txio)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
					return
				}
				txReceipt = fullTx.FullTx
			}
			tx.Receipt = txReceipt
			common.ValidateAndWriteResponse(tx, err, c.Writer)
			return
		}

	}

	common.ValidateAndWriteResponse(tx, err, c.Writer)
}

// CompleteTx process signature for a transaction requiring ECDSA type signature
func CompleteStakeTx(c *gin.Context) {
	var txInput l1common.TxInputs
	c.ShouldBindBodyWith(&txInput, binding.JSON)

	messageHash := txInput.Hash

	idHash := c.Request.URL.Query().Get("idHash")
	if idHash == "" {
		idHash = messageHash
	}

	tx, err := gateways.ReadTx(idHash, gateways.DB.Transactions)
	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadTxError, err)), c.Writer)
		return
	}

	if l1common.BlockchainsMap[tx.BlockchainId] == common.ECDSA {

		var signature l1common.EcdsaSignature
		err := json.Unmarshal([]byte(txInput.Signature), &signature)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)), c.Writer)
			return
		}

		signatureJSON, err := json.Marshal(signature)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.MarshallError, err)), c.Writer)
			return
		}

		err = gateways.UpdateTxInputSignature(idHash, messageHash, string(signatureJSON), gateways.DB.Transactions)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.WriteTxError, err)), c.Writer)
			return
		}

		sigNum := 0
		for i, val := range tx.Inputs {
			if val.Hash == messageHash {
				tx.Inputs[i].Signature = string(signatureJSON)
				sigNum++
			} else {
				if val.Signature != "" {
					sigNum++
				}
			}
		}

		if len(tx.Inputs) == sigNum {
			var txReceipt string
			var fullSignature l1common.EcdsaSignature
			err := json.Unmarshal([]byte(tx.Inputs[0].Signature), &fullSignature)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)), c.Writer)
				return
			}

			switch op := tx.BlockchainId; op {
			case blockchains.Ethereum:
				fullTx, err := blockchains.CompleteETHTx(messageHash, fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
					return
				}
				txReceipt = fullTx.Hash().Hex()
			case blockchains.Avalanche:
				fullTx, err := blockchains.CompleteAvaxStakeTx(messageHash, fullSignature)
				if err != nil {
					common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.CommitTxError, err)), c.Writer)
					return
				}
				txReceipt = fullTx.Receipt
			}
			tx.Receipt = txReceipt
			common.ValidateAndWriteResponse(tx, err, c.Writer)
			return
		}

	}

	common.ValidateAndWriteResponse(tx, err, c.Writer)
}

// GetAddress return the hex address for user for specified token and account name
func GetAddress(c *gin.Context) {
	userId := c.Param("userId")
	blockchainId := c.Param("blockchainId")
	accountName := c.Param("accountName")

	var result interface{}
	var err error
	if l1common.BlockchainsMap[blockchainId] == common.ECDSA {
		share, err := gateways.ReadECDSAShare(userId, blockchainId, accountName, gateways.DB.KeyShares)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadMPCShareError, err)), c.Writer)
			return
		}

		pubKey, err := getPublicKey(share)

		switch op := blockchainId; op {
		case blockchains.Ethereum:
			result, err = blockchains.GetETHBalances(crypto.PubkeyToAddress(pubKey))
		case blockchains.Avalanche:
			result, err = blockchains.GetAvaxBalances(pubKey)
		case blockchains.Bitcoin:
			result, err = blockchains.GetBTCBalances(pubKey)
		}

	} else if l1common.BlockchainsMap[blockchainId] == common.EDDSA {
		share, err := gateways.ReadEDDSAShare(userId, blockchainId, accountName, gateways.DB.KeyShares)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadMPCShareError, err)), c.Writer)
			return
		}

		pkRawDecodedBytes, err := base64.StdEncoding.DecodeString(share.PK)
		if err != nil {
			log.Error(err)
		}

		switch op := blockchainId; op {
		case blockchains.Algorand:
			result, err = blockchains.GetALGOBalance(pkRawDecodedBytes)
		}

	}

	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.GetBalanceError, err)), c.Writer)
		return
	}

	common.ValidateAndWriteResponse(result, err, c.Writer)
}

// getPublicKey converts PK data store in key vault into common format
// for blockchain integrations
func getPublicKey(share l1common.KeyShare) (ecdsa.PublicKey, error) {
	var pk curves.EcPoint
	var pubKey ecdsa.PublicKey
	err := pk.UnmarshalJSON([]byte(share.ShareData.PK))
	if err != nil {
		return pubKey, errors.BuildErrMsg(errors.UnmarshallError, err)
	}

	pubKey = ecdsa.PublicKey{
		Curve: pk.Curve,
		X:     pk.X,
		Y:     pk.Y,
	}

	return pubKey, nil
}

// Getting current suggested fees for all currencyes
func GetAllChainsFees(c *gin.Context) {
	fees := GetFees()
	common.ValidateAndWriteResponse(fees, nil, c.Writer)
}

func GetFees() l1common.ChainsFees {
	log.Info("Getting fees from blockchains")
	fees := l1common.ChainsFees{}
	fees.BTC.SafeFee = new(big.Int).SetUint64(blockchains.GetBTCFee())
	fees.AVAX.SafeFee = evm.GetAvaxTxFee()

	ethFeeProvider := evm.EthereumLikeChainsFee{l1common.L1Configurations.Ethereum.EtherscanURLGasOracle, l1common.L1Configurations.Ethereum.EtherscanAPIKEY}

	ethGasFees, err := ethFeeProvider.GetGasOracle()
	if err != nil {
		log.Error(err)
	}

	fees.ETH.SafeFee = ethGasFees.SafeGasPrice
	fees.ETH.ProposeFee = ethGasFees.ProposeGasPrice
	fees.ETH.FastFee = ethGasFees.FastGasPrice

	bscFeeProvider := evm.EthereumLikeChainsFee{l1common.L1Configurations.BSC.BscScanUrl, l1common.L1Configurations.BSC.BscScanApiKey}
	bscGasFees, err := bscFeeProvider.GetGasOracle()
	if err != nil {
		log.Error(err)
	}

	fees.BNB.SafeFee = bscGasFees.SafeGasPrice
	fees.BNB.ProposeFee = bscGasFees.ProposeGasPrice
	fees.BNB.FastFee = bscGasFees.FastGasPrice

	polyFeeProvider := evm.EthereumLikeChainsFee{l1common.L1Configurations.Polygon.PolygonScanUrl, l1common.L1Configurations.Polygon.PolygonScanApiKey}
	log.Info("Getting fees from Polygon", polyFeeProvider)
	polyGasFees, err := polyFeeProvider.GetGasOracle()
	if err != nil {
		log.Error(err)
	}

	fees.MATIC.SafeFee = polyGasFees.SafeGasPrice
	fees.MATIC.ProposeFee = polyGasFees.ProposeGasPrice
	fees.MATIC.FastFee = polyGasFees.FastGasPrice

	fees.ALGO.FastFee = new(big.Int).SetUint64(blockchains.GetAlgoTxFee())

	_, err = gateways.JsonDataStorage("unique_ID_gas_fees", fees)
	if err != nil {
		log.Error("ERROR WRITING FEES: ", err)
	}
	log.Info("Fees written", fees)

	return fees
}

func uniQuote(blockchainId string,
	tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {

	var err error
	var amountOut float64

	if l1common.BlockchainsMap[blockchainId] == common.ECDSA {

		switch op := blockchainId; op {
		case blockchains.Ethereum:
			amountOut, err = blockchains.EthereumUniQuote(tokenInId, amount, tokenOutId)
		case blockchains.Polygon:
			amountOut, err = blockchains.PolygonUniQuote(tokenInId, amount, tokenOutId)
		case blockchains.BSC:
			amountOut, err = blockchains.BinanceUniQuote(tokenInId, amount, tokenOutId)
		default:
			err = errors.New("invalid blockchain choice")
		}

	} else {
		err = errors.New("invalid request")
	}

	return amountOut, err
}

func oneInchQuote(blockchainId string,
	tokenInId string,
	amount float64,
	tokenOutId string) (float64, error) {

	var err error
	var amountOut float64

	if l1common.BlockchainsMap[blockchainId] == common.ECDSA {

		switch op := blockchainId; op {
		case blockchains.Ethereum:
			amountOut, err = blockchains.EthereumOneInchQuote(tokenInId, amount, tokenOutId)
		case blockchains.Polygon:
			amountOut, err = blockchains.PolygonOneInchQuote(tokenInId, amount, tokenOutId)
		case blockchains.BSC:
			amountOut, err = blockchains.BinanceOneInchQuote(tokenInId, amount, tokenOutId)
		default:
			err = errors.New("invalid blockchain choice")
		}

	} else {
		err = errors.New("invalid request")
	}

	return amountOut, err
}

func UniQuote(c *gin.Context) {
	blockchainId := c.Param("blockchainId")
	tokenInId := c.Param("tokenInId")
	tokenOutId := c.Param("tokenOutId")
	amountStr := c.Param("amount")

	var result interface{}

	amountIn, err := strconv.ParseFloat(amountStr, 64)
	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.IncorrectInputs, err)), c.Writer)
		return
	}

	amountOut, err := uniQuote(blockchainId, tokenInId, amountIn, tokenOutId)
	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.IncorrectInputs, err)), c.Writer)
		return
	}

	result = amountOut

	common.ValidateAndWriteResponse(result, err, c.Writer)
}

func OneInchQuote(c *gin.Context) {
	blockchainId := c.Param("blockchainId")
	tokenInId := c.Param("tokenInId")
	tokenOutId := c.Param("tokenOutId")
	amountStr := c.Param("amount")

	var result interface{}

	amountIn, err := strconv.ParseFloat(amountStr, 64)
	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.IncorrectInputs, err)), c.Writer)
		return
	}

	amountOut, err := oneInchQuote(blockchainId, tokenInId, amountIn, tokenOutId)
	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.IncorrectInputs, err)), c.Writer)
		return
	}

	result = amountOut

	common.ValidateAndWriteResponse(result, err, c.Writer)
}

func Quote(c *gin.Context) {
	blockchainId := c.Param("blockchainId")
	tokenInId := c.Param("tokenInId")
	tokenOutId := c.Param("tokenOutId")
	amountStr := c.Param("amount")

	result := make(map[string]float64)

	amountIn, err := strconv.ParseFloat(amountStr, 64)
	if err != nil {
		common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.IncorrectInputs, err)), c.Writer)
		return
	}

	oneInchAmountOut, err := oneInchQuote(blockchainId, tokenInId, amountIn, tokenOutId)
	if err == nil {
		result["oneInch"] = oneInchAmountOut
	}

	uniAmountOut, err := uniQuote(blockchainId, tokenInId, amountIn, tokenOutId)
	if err == nil {
		result["uni"] = uniAmountOut
	}

	common.ValidateAndWriteResponse(result, err, c.Writer)
}
