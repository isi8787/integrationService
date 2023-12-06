package blockchains

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"

	l1common "finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"

	l1evm "finco/l1integration/blockchains/evm"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/formatting"
	"github.com/ava-labs/avalanchego/utils/formatting/address"
	"github.com/ava-labs/avalanchego/utils/hashing"
	"github.com/ava-labs/avalanchego/vms/avm/fxs"
	"github.com/ava-labs/avalanchego/vms/avm/txs"
	"github.com/ava-labs/avalanchego/vms/components/avax"
	"github.com/ava-labs/avalanchego/vms/components/verify"
	"github.com/ava-labs/avalanchego/vms/nftfx"
	"github.com/ava-labs/avalanchego/vms/platformvm"
	"github.com/ava-labs/avalanchego/vms/platformvm/stakeable"
	ptxs "github.com/ava-labs/avalanchego/vms/platformvm/txs"
	"github.com/ava-labs/avalanchego/vms/platformvm/validator"
	"github.com/ava-labs/avalanchego/vms/propertyfx"
	"github.com/ava-labs/avalanchego/vms/secp256k1fx"
	evm "github.com/ava-labs/coreth/plugin/evm"
	"github.com/btcsuite/btcutil/bech32"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ripemd160"
)

var avalancheChainIDInt = l1common.L1Configurations.ChainIDs.Avalanche.TestNet
var fujiCChainURI string = l1common.L1Configurations.Infura.Fuji
var fujiChains l1common.AvalancheConfigurations = l1common.L1Configurations.Quicknode.Fuji

// AVAXTx prepare transaction for sending Avax in the C-Chain from an eth style address to another
func AVAXTx(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey) (l1common.BasicTx, error) {
	chainID := big.NewInt(avalancheChainIDInt)
	avx := l1evm.EthereumLikeChainsFee{l1evm.ApiUrl, l1evm.ApiKey}
	gasLimit := avx.GetBasicTxGasLimit()
	txCreator, err := l1evm.NewEVMTxCreator(chainID, fujiCChainURI, gateways.DB.Ethereum, gateways.DB.Transactions, gasLimit.Uint64(), tx.BlockchainId)
	if err != nil {
		return tx, err
	}
	return txCreator.CreateEthereumBasedTx(tx, pubKeyK)
}

// CompleteTx provides single function for submiting transaction to infrastructure provider
// after signature generated.
func CompleteAvaxTx(txHash string, signature l1common.EcdsaSignature) (*types.Transaction, error) {
	chainID := big.NewInt(avalancheChainIDInt)
	txBroadCaster, err := l1evm.NewEVMTxBroadcaster(chainID, fujiCChainURI, gateways.DB.Ethereum, gateways.DB.Transactions)
	if err != nil {
		return nil, err
	}
	return txBroadCaster.CompleteTx(txHash, signature)
}

// GetAvaxBalances support function to retrieve balances from
// C-Chain, X-Chain and P-Chain for a public key associated with
// an AVAX address
func GetAvaxBalances(pubKeyK ecdsa.PublicKey) (interface{}, error) {
	var result []l1common.AccountData

	var pChain l1common.AccountData
	var xChain l1common.AccountData
	var cChain l1common.AccountData

	// Get AVM style address
	encoded, err := avaxParseServiceAddresses(pubKeyK)
	if err != nil {
		return result, err
	}

	pChain.Address = ("P-" + encoded)
	xChain.Address = ("X-" + encoded)

	xParams := gateways.AvaxParams{Address: xChain.Address, AssetID: "AVAX"}
	xchainRequest := gateways.QuicknodeRequest{Jsonrpc: "2.0", Id: 1, Method: "avm.getBalance", Params: xParams}
	xchainRequestBytes, err := json.Marshal(xchainRequest)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	xChainBalance, err := getAvaxBalance(&gateways.RequestParams{Method: gateways.MethodPost, Url: fujiChains.XChain, Body: bytes.NewBuffer(xchainRequestBytes)})
	if err != nil {
		return result, err
	}
	xChain.Balance = nAvaxToAvax(xChainBalance).String()

	//This gets UTXOs
	pParams := gateways.AvaxParams{Address: pChain.Address, AssetID: "AVAX"}
	pchainRequest := gateways.QuicknodeRequest{Jsonrpc: "2.0", Id: 1, Method: "platform.getBalance", Params: pParams}
	pchainRequestBytes, err := json.Marshal(pchainRequest)
	if err != nil {
		return result, err
	}
	pChainBalance, err := getAvaxBalance(&gateways.RequestParams{Method: gateways.MethodPost, Url: fujiChains.PChain, Body: bytes.NewBuffer(pchainRequestBytes)})
	if err != nil {
		return result, err
	}
	pChain.Balance = nAvaxToAvax(pChainBalance).String()

	//This gets Staked value
	stakedParams := gateways.UTXOParams{Addresses: []string{pChain.Address}, Limit: 20, SourceChain: "P", Encoding: "hex"}
	stakeRequest := gateways.QuicknodeRequest{Jsonrpc: "2.0", Id: 1, Method: "platform.getStake", Params: stakedParams}
	stakeRequestBytes, err := json.Marshal(stakeRequest)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	stakeBalance, err := getStakeBalance(&gateways.RequestParams{Method: gateways.MethodPost, Url: fujiChains.PChain, Body: bytes.NewBuffer(stakeRequestBytes)})
	if err != nil {
		return result, err
	}
	pChain.StakeBalance = nAvaxToAvax(stakeBalance).String()

	// Get ETH style address
	fromAddress := crypto.PubkeyToAddress(pubKeyK)
	cChain.Address = fromAddress.Hex()
	client, err := ethclient.Dial(fujiCChainURI)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	avaxBalance, err := client.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.ClientError, err)
	}

	cChain.Balance = WeiToEther(avaxBalance).String()

	result = append(result, cChain)
	result = append(result, xChain)
	result = append(result, pChain)
	return result, nil
}

func SHARipemd(b []byte) []byte {

	//sha hashing of the input
	var h hash.Hash = sha256.New()
	h.Write(b)

	//ripemd hashing of the sha hash
	var h2 hash.Hash = ripemd160.New()
	h2.Write(h.Sum(nil))

	return h2.Sum(nil) //return
}

// getAvaxBalance queries avalanche to get balance for all 3 chains
// using quicknode infrastructure
func getAvaxBalance(opts *gateways.RequestParams) (*big.Int, error) {
	balance := new(big.Int)

	quickNodeResponse, err := doQuickNodeRequest(opts)
	if err != nil {
		return balance, err
	}

	gweibalance := quickNodeResponse.Result.Balance
	balance.SetString(gweibalance, 10)
	return balance, nil

}

// getStakeBalance queries avalanche P-chain to get staked balance
// for an address
func getStakeBalance(opts *gateways.RequestParams) (*big.Int, error) {
	balance := new(big.Int)
	quickNodeResponse, err := doQuickNodeRequest(opts)
	if err != nil {
		return balance, err
	}

	gweibalance := quickNodeResponse.Result.Staked
	balance.SetString(gweibalance, 10)
	return balance, nil

}

// doQuickNodeRequest performs http request against quicknode
// and returns standard response body
func doQuickNodeRequest(opts *gateways.RequestParams) (gateways.QuicknodeResponse, error) {
	var quickNodeResponse gateways.QuicknodeResponse

	req, err := http.NewRequest(opts.Method, opts.Url, opts.Body)
	if err != nil {
		return quickNodeResponse, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}

	resp, err := gateways.HttpRequest(req, opts)
	if err != nil {
		return quickNodeResponse, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return quickNodeResponse, errors.BuildAndLogErrorMsg(errors.DecodeBodyError, err)
	}

	err = json.Unmarshal(respBody, &quickNodeResponse)
	if err != nil {
		return quickNodeResponse, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	return quickNodeResponse, nil
}

// avaxGetUTXOs queries avalanche using quicknode infrastructure
// to get UTXOs for target chain supporting cross chain atomic
// transactions.
func avaxGetUTXOs(blockchainId, sourceChain, fromAddress string) ([]avax.UTXO, error) {
	var result []avax.UTXO
	address := blockchainId + "-" + fromAddress
	var url, method string
	if blockchainId == "X" {
		url = fujiChains.XChain
		method = "avm.getUTXOs"
	} else if blockchainId == "P" {
		url = fujiChains.PChain
		method = "platform.getUTXOs"
	} else {
		url = fujiChains.CChain
		method = "avax.getUTXOs"
	}

	params := gateways.UTXOParams{Addresses: []string{address}, Limit: 5, Encoding: "hex", SourceChain: sourceChain}
	request := gateways.QuicknodeRequest{Jsonrpc: "2.0", Id: 1, Method: method, Params: params}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	opts := &gateways.RequestParams{Method: gateways.MethodPost, Url: url, Body: bytes.NewBuffer(requestBytes)}
	req, err := http.NewRequest(opts.Method, opts.Url, opts.Body)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}

	resp, err := gateways.HttpRequest(req, opts)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.DecodeBodyError, err)
	}

	var quickNodeResponse gateways.QuicknodeResponse

	err = json.Unmarshal(respBody, &quickNodeResponse)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	utxosDecoded := make([]avax.UTXO, len(quickNodeResponse.Result.UTXOs))

	for i, val := range quickNodeResponse.Result.UTXOs {
		utxoBytes, err := formatting.Decode(formatting.Hex, val)
		if err != nil {
			return result, errors.BuildAndLogErrorMsg(errors.HexDecodeError, err)
		}

		var utxo avax.UTXO
		_, err = platformvm.Codec.Unmarshal(utxoBytes, &utxo)
		if err != nil {
			return result, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
		}

		utxosDecoded[i] = utxo
	}

	return utxosDecoded, nil

}

// SendAVMChainAvax prepares same chain transfers for the X-Chain and P-Chain
// The function builds the inputs and outputs needed to complete the transfer
// and organizes them into multiple inputs to collect multiple signatures from
// custody services
func SendAVMChainAvax(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey, chainId string) (l1common.BasicTx, error) {
	amount, err := strconv.ParseFloat(tx.Value, 64)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	nAmount := amount * 1000000000 //Convert to nAvax

	// Parse public key into AVAX format
	fromAddrs, err := avaxParseServiceAddresses(pubKeyK)
	if err != nil {
		return tx, err
	}

	// Load user's UTXOs for the origin chain
	utxosDecoded, err := avaxGetUTXOs(chainId, chainId, fromAddrs)
	if err != nil {
		return tx, err
	}

	// Parse the sender address into short ID format
	fromShort, err := address.ParseToID(chainId + avaxSeperator + fromAddrs)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	// Parse the the blockchain id to short ID format
	blockchainid, err := ids.FromString(chainIdMap[chainId]) // Fuji ID
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	//Fixed fee for AVAX
	tx.Fee = float64(1000000)
	avaxAssetID, err := ids.FromString(avaxID) // AVAX asset ID
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	ins := []*avax.TransferableInput{}
	ins, inputAmounts, err := prepareInputs(ins, utxosDecoded, uint64(nAmount), uint64(tx.Fee))
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.InputsError, err)
	}

	out1 := avax.TransferableOutput{
		Asset: avax.Asset{ID: avaxAssetID},
		Out: &secp256k1fx.TransferOutput{
			Amt: inputAmounts - uint64(nAmount) - uint64(tx.Fee),
			OutputOwners: secp256k1fx.OutputOwners{
				Threshold: 1,
				Addrs:     []ids.ShortID{fromShort},
			},
		},
	}

	// Format the recipient address
	to, err := address.ParseToID(tx.ToAddress)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	out2 := avax.TransferableOutput{
		Asset: avax.Asset{ID: avaxAssetID},
		Out: &secp256k1fx.TransferOutput{
			Amt: uint64(nAmount),
			OutputOwners: secp256k1fx.OutputOwners{
				Threshold: 1,
				Addrs:     []ids.ShortID{to},
			},
		},
	}

	parser, err := txs.NewParser([]fxs.Fx{
		&secp256k1fx.Fx{},
		&nftfx.Fx{},
		&propertyfx.Fx{},
	})

	c := parser.Codec()

	outs := []*avax.TransferableOutput{&out1, &out2}
	avax.SortTransferableOutputs(outs, parser.Codec())

	justBaseTx := avax.BaseTx{
		NetworkID:    5,
		BlockchainID: blockchainid,
		Outs:         outs,
		Ins:          ins,
	}

	baseunsignedBytes, err := c.Marshal(CodecVersion, &justBaseTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	unsignedtx := txs.Tx{Unsigned: &txs.BaseTx{BaseTx: justBaseTx}}

	unsignedBytes, err := c.Marshal(CodecVersion, &unsignedtx.Unsigned)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	txHex := hex.EncodeToString(baseunsignedBytes)
	tx.FullTx = txHex

	hash := hashing.ComputeHash256(unsignedBytes)
	tx.TxHash = "0x" + hex.EncodeToString(hash)
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: tx.TxHash, InputIndex: 0}}
	tx.Status = l1common.TxCreated

	err = gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil
}

// CompleteAvaxAVMTx provides single function for submiting transaction to infrastructure provider
// Utilized for same chain transfers for P-chain and X-chain
func CompleteAvaxAVMTx(messageHash string, signature l1common.EcdsaSignature, chainId string) (l1common.BasicTx, error) {
	tx, err := gateways.ReadTx(messageHash, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ReadTxError, err)
	}

	unsignedBytes, err := hex.DecodeString(tx.FullTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.HexDecodeError, err)
	}

	var baseTx avax.BaseTx
	parser, err := txs.NewParser([]fxs.Fx{
		&secp256k1fx.Fx{},
		&nftfx.Fx{},
		&propertyfx.Fx{},
	})

	c := parser.Codec()
	_, err = c.Unmarshal(unsignedBytes, &baseTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	fullUnsignedTx := txs.Tx{Unsigned: &txs.BaseTx{BaseTx: baseTx},
		Creds: []*fxs.FxCredential{},
	}

	sigbytes := sigToBytes(signature)

	cred := &secp256k1fx.Credential{
		Sigs: make([][65]byte, 1),
	}

	copy(cred.Sigs[0][:], sigbytes)

	for _, _ = range baseTx.Ins {
		fullUnsignedTx.Creds = append(fullUnsignedTx.Creds, &fxs.FxCredential{Verifiable: cred})
	}

	signedBytes, err := c.Marshal(CodecVersion, fullUnsignedTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	fullUnsignedTx.Initialize(unsignedBytes, signedBytes)

	signatureJSON, _ := json.Marshal(signature)
	tx.FullTx = hex.EncodeToString(signedBytes)
	tx.Inputs[0].Signature = string(signatureJSON)
	tx.Status = l1common.TxSubmitted

	signedBytes, err = c.Marshal(CodecVersion, fullUnsignedTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	hexstr2, err := formatting.EncodeWithChecksum(formatting.Hex, signedBytes)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.HexEncodeError, err)
	}

	receipt, err := avaxAVMIssueTx(hexstr2, chainId)
	if err != nil {
		return tx, err
	}
	tx.Status = l1common.TxSubmitted
	tx.Receipt = receipt
	err = gateways.UpdateTx(messageHash, tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil
}

// CrossChainAvaxExport prepares cross chain transfers export for the C-Chain, X-Chain & P-Chain
// The function builds the inputs and outputs needed to complete the transfer
// and organizes them into multiple inputs to collect multiple signatures from
// custody services
func CrossChainAvaxExport(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey, originChain, targetChain string) (l1common.BasicTx, error) {
	amount, err := strconv.ParseFloat(tx.Value, 64)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	nAmount := uint64(amount*1000000000) + uint64(1000000) //Convert to nAvax and add extra fee for import round

	// Parse the from addresses
	fromAddrs, err := avaxParseServiceAddresses(pubKeyK)
	if err != nil {
		return tx, err
	}

	// Load user's UTXOs
	utxosDecoded, err := avaxGetUTXOs(originChain, originChain, fromAddrs)
	if err != nil {
		return tx, err
	}

	// Parse the to address
	fromShort, err := address.ParseToID(originChain + avaxSeperator + fromAddrs)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	// Parse the to the blockchain id short
	blockchainid, err := ids.FromString(chainIdMap[originChain]) // Fuji ID
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	tx.Fee = float64(1000000)
	avaxAssetID, err := ids.FromString(avaxID) // AVAX aasset ID
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	ins := []*avax.TransferableInput{}
	ins, inputAmounts, err := prepareInputs(ins, utxosDecoded, uint64(nAmount), uint64(tx.Fee))
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.InputsError, err)
	}

	out1 := avax.TransferableOutput{
		Asset: avax.Asset{ID: avaxAssetID},
		Out: &secp256k1fx.TransferOutput{
			Amt: inputAmounts - uint64(nAmount) - uint64(tx.Fee),
			OutputOwners: secp256k1fx.OutputOwners{
				Threshold: 1,
				Addrs:     []ids.ShortID{fromShort},
			},
		},
	}

	// Parse the to address
	toShort, err := address.ParseToID(targetChain + avaxSeperator + fromAddrs)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	out2 := avax.TransferableOutput{
		Asset: avax.Asset{ID: avaxAssetID},
		Out: &secp256k1fx.TransferOutput{
			Amt: uint64(nAmount),
			OutputOwners: secp256k1fx.OutputOwners{
				Threshold: 1,
				Addrs:     []ids.ShortID{toShort},
			},
		},
	}

	parser, err := txs.NewParser([]fxs.Fx{
		&secp256k1fx.Fx{},
		&nftfx.Fx{},
		&propertyfx.Fx{},
	})

	c := parser.Codec()

	outs := []*avax.TransferableOutput{&out1}
	exportout := []*avax.TransferableOutput{&out2}
	avax.SortTransferableOutputs(outs, parser.Codec())

	baseTx := avax.BaseTx{
		NetworkID:    5,
		BlockchainID: blockchainid,
		Outs:         outs,
		Ins:          ins,
	}

	// Parse the to the blockchain id short
	destinationblockchainid, err := ids.FromString(chainIdMap[targetChain]) // Fuji ID
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	if originChain == "X" {
		exportTx := txs.ExportTx{
			BaseTx:           txs.BaseTx{BaseTx: baseTx},
			DestinationChain: destinationblockchainid,
			ExportedOuts:     exportout,
		}

		exportunsignedBytes, err := c.Marshal(CodecVersion, &exportTx)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		unsignedtx := txs.Tx{Unsigned: &exportTx}

		unsignedBytes, err := c.Marshal(CodecVersion, &unsignedtx.Unsigned)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		txHex := hex.EncodeToString(exportunsignedBytes)
		tx.FullTx = txHex

		hash := hashing.ComputeHash256(unsignedBytes)
		tx.TxHash = "0x" + hex.EncodeToString(hash)

	} else if originChain == "P" {
		exportTx := ptxs.ExportTx{
			BaseTx:           ptxs.BaseTx{BaseTx: baseTx},
			DestinationChain: destinationblockchainid,
			ExportedOutputs:  exportout,
		}

		exportunsignedBytes, err := platformvm.Codec.Marshal(CodecVersion, &exportTx)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		unsignedtx := ptxs.Tx{Unsigned: &exportTx}

		unsignedBytes, err := platformvm.Codec.Marshal(CodecVersion, &unsignedtx.Unsigned)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		txHex := hex.EncodeToString(exportunsignedBytes)
		tx.FullTx = txHex

		hash := hashing.ComputeHash256(unsignedBytes)
		tx.TxHash = "0x" + hex.EncodeToString(hash)

	} else if originChain == "C" {

		fromAddress := crypto.PubkeyToAddress(pubKeyK)

		client, err := ethclient.Dial(fujiCChainURI) // TODO: change to config.json
		if err != nil {
			log.Error(err)
		}
		//TODO need to cache nonce locally to avoid duplicating nonce for transactions that have not finish completing on the blockchain
		nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.GetPendingNocceError, err)
		}

		avaxBalance, err := client.BalanceAt(context.Background(), fromAddress, nil)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.ClientError, err)
		}

		x2cRate := big.NewInt(x2cRateInt64)
		cChainBalance := new(big.Int).Div(avaxBalance, x2cRate).Uint64()

		gasLimit := uint64(21000)
		gasPrice, err := client.SuggestGasPrice(context.Background())
		if err != nil {
			log.Fatal(err)
			return tx, err
		}

		gasFee := new(big.Int).Div((gasPrice), x2cRate).Uint64()

		if nAmount < cChainBalance {
			cChainBalance = nAmount
		} else {
			return tx, fmt.Errorf("Insufficient funds")
		}

		exportTx := evm.UnsignedExportTx{
			Ins: []evm.EVMInput{
				evm.EVMInput{
					Address: fromAddress,
					Amount:  (cChainBalance + uint64(tx.Fee) + gasFee + gasLimit),
					AssetID: avaxAssetID,
					Nonce:   nonce,
				},
			},
			NetworkID:        5,
			BlockchainID:     blockchainid,
			DestinationChain: destinationblockchainid,
			ExportedOutputs:  exportout,
		}

		tx.Fee += float64(gasFee)

		unsignedtx := evm.Tx{UnsignedAtomicTx: &exportTx}

		exportunsignedBytes, err := evm.Codec.Marshal(EVMCodecVersion, &exportTx)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		unsignedBytes, err := evm.Codec.Marshal(EVMCodecVersion, &unsignedtx.UnsignedAtomicTx)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		txHex := hex.EncodeToString(exportunsignedBytes)
		tx.FullTx = txHex

		hash := hashing.ComputeHash256(unsignedBytes)
		tx.TxHash = "0x" + hex.EncodeToString(hash)
	}

	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: tx.TxHash, InputIndex: 0}}
	tx.Status = l1common.TxCreated

	err = gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil
}

// CrossChainAvaxImport prepares cross chain transfers import for the C-Chain, X-Chain & P-Chain
// The function builds the inputs and outputs needed to complete the transfer
// and organizes them into multiple inputs to collect multiple signatures from
// custody services
func CrossChainAvaxImport(tx l1common.BasicTx, pubKeyK ecdsa.PublicKey, originChain, targetChain string) (l1common.BasicTx, error) {
	amount, err := strconv.ParseFloat(tx.Value, 64)
	if err != nil {
		return tx, err
	}
	nAmount := amount * 1000000000 //Convert to nAvax

	// Parse the from addresses
	fromAddrs, err := avaxParseServiceAddresses(pubKeyK)
	if err != nil {
		return tx, err
	}

	// Load user's UTXOs
	utxosDecoded, err := avaxGetUTXOs(targetChain, originChain, fromAddrs)
	if err != nil {
		return tx, err
	}

	// Parse the to the blockchain id short
	blockchainid, err := ids.FromString(chainIdMap[targetChain]) // Fuji ID
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	tx.Fee = float64(1000000)
	avaxAssetID, err := ids.FromString(avaxID) // AVAX aasset ID
	if err != nil {
		return tx, fmt.Errorf("problem parsing avax asset id: %w", err)
	}

	ins := []*avax.TransferableInput{}
	importInputs := []*avax.TransferableInput{}
	importInputs, _, err = prepareInputs(ins, utxosDecoded, uint64(nAmount), uint64(tx.Fee))
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.InputsError, err)
	}

	// Parse the to address
	toShort, err := address.ParseToID(targetChain + avaxSeperator + fromAddrs)
	if err != nil {
		return tx, fmt.Errorf("problem parsing address: %w", err)
	}

	out1 := avax.TransferableOutput{
		Asset: avax.Asset{ID: avaxAssetID},
		Out: &secp256k1fx.TransferOutput{
			Amt: uint64(nAmount),
			OutputOwners: secp256k1fx.OutputOwners{
				Threshold: 1,
				Addrs:     []ids.ShortID{toShort},
			},
		},
	}

	outs := []*avax.TransferableOutput{&out1}

	baseTx := avax.BaseTx{
		NetworkID:    5,
		BlockchainID: blockchainid,
		Outs:         outs,
		Ins:          ins,
	}

	originblockchainid, err := ids.FromString(chainIdMap[originChain]) // Fuji ID
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	//TODO: need to change to interfaces to removew duplicate code
	if targetChain == "P" {
		// Parse the to the blockchain id short

		importTx := ptxs.ImportTx{
			BaseTx:         ptxs.BaseTx{BaseTx: baseTx},
			SourceChain:    originblockchainid,
			ImportedInputs: importInputs,
		}

		importunsignedBytes, err := platformvm.Codec.Marshal(CodecVersion, &importTx)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		unsignedtx := ptxs.Tx{Unsigned: &importTx}

		unsignedBytes, err := platformvm.Codec.Marshal(CodecVersion, &unsignedtx.Unsigned)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		txHex := hex.EncodeToString(importunsignedBytes)
		tx.FullTx = txHex

		hash := hashing.ComputeHash256(unsignedBytes)
		tx.TxHash = "0x" + hex.EncodeToString(hash)
	} else if targetChain == "X" {
		parser, err := txs.NewParser([]fxs.Fx{
			&secp256k1fx.Fx{},
			&nftfx.Fx{},
			&propertyfx.Fx{},
		})
		c := parser.Codec()

		importTx := txs.ImportTx{
			BaseTx:      txs.BaseTx{BaseTx: baseTx},
			SourceChain: originblockchainid,
			ImportedIns: importInputs,
		}

		importunsignedBytes, err := c.Marshal(CodecVersion, &importTx)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		unsignedtx := txs.Tx{Unsigned: &importTx}

		unsignedBytes, err := c.Marshal(CodecVersion, &unsignedtx.Unsigned)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		txHex := hex.EncodeToString(importunsignedBytes)
		tx.FullTx = txHex

		hash := hashing.ComputeHash256(unsignedBytes)
		tx.TxHash = "0x" + hex.EncodeToString(hash)
	} else if targetChain == "C" {
		toCAddress := crypto.PubkeyToAddress(pubKeyK)

		// Create the transaction
		importTx := &evm.UnsignedImportTx{
			NetworkID:    5,
			BlockchainID: blockchainid,
			Outs: []evm.EVMOutput{
				evm.EVMOutput{
					Address: toCAddress,
					Amount:  uint64(nAmount),
					AssetID: avaxAssetID,
				},
			},
			ImportedInputs: importInputs,
			SourceChain:    originblockchainid,
		}

		importunsignedBytes, err := evm.Codec.Marshal(CodecVersion, &importTx)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		unsignedtx := &evm.Tx{UnsignedAtomicTx: importTx}

		unsignedBytes, err := evm.Codec.Marshal(CodecVersion, &unsignedtx.UnsignedAtomicTx)
		if err != nil {
			return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
		}

		txHex := hex.EncodeToString(importunsignedBytes)
		tx.FullTx = txHex

		hash := hashing.ComputeHash256(unsignedBytes)
		tx.TxHash = "0x" + hex.EncodeToString(hash)

	}

	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: tx.TxHash, InputIndex: 0}}
	tx.Status = l1common.TxCreated

	err = gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil
}

// CompleteAvaxCrossChainTx provides single function for submiting transaction to infrastructure provider
// for all cross chain operations. Appends signatures generated from custody service.
func CompleteAvaxCrossChainTx(messageHash string, signature l1common.EcdsaSignature, originChain, targetChain, txio string) (l1common.BasicTx, error) {
	tx, err := gateways.ReadTx(messageHash, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ReadTxError, err)
	}

	unsignedBytes, err := hex.DecodeString(tx.FullTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsgWithData(errors.TxDecodingError, err, tx.FullTx)
	}

	xChainUnsignedTx := txs.Tx{Unsigned: nil,
		Creds: []*fxs.FxCredential{},
	}

	pChainUnsignedTx := ptxs.Tx{Unsigned: nil,
		Creds: []verify.Verifiable{}}

	cChainUnsignedTx := evm.Tx{
		UnsignedAtomicTx: nil,
		Creds:            []verify.Verifiable{}}

	sigbytes := sigToBytes(signature)

	cred := &secp256k1fx.Credential{
		Sigs: make([][65]byte, 1),
	}

	copy(cred.Sigs[0][:], sigbytes)

	parser, err := txs.NewParser([]fxs.Fx{
		&secp256k1fx.Fx{},
		&nftfx.Fx{},
		&propertyfx.Fx{},
	})
	c := parser.Codec()

	var submitTo string
	var signedBytes []byte
	var hexstr2 string
	//TODO need to move interface to avoid code duplication
	if txio == "export" {
		if originChain == "X" {
			submitTo = originChain
			var exportTx txs.ExportTx

			_, err = c.Unmarshal(unsignedBytes, &exportTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
			}

			xChainUnsignedTx.Unsigned = &exportTx

			for _, _ = range exportTx.Ins {
				xChainUnsignedTx.Creds = append(xChainUnsignedTx.Creds, &fxs.FxCredential{Verifiable: cred})
			}

			signedBytes, err = c.Marshal(CodecVersion, xChainUnsignedTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
			}

			xChainUnsignedTx.Initialize(unsignedBytes, signedBytes)

			hexstr2, err = formatting.EncodeWithChecksum(formatting.Hex, xChainUnsignedTx.Bytes())
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.HexEncodeError, err)
			}
		} else if originChain == "P" {
			submitTo = originChain
			var exportTx ptxs.ExportTx

			_, err = platformvm.Codec.Unmarshal(unsignedBytes, &exportTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
			}

			pChainUnsignedTx.Unsigned = &exportTx

			for _, _ = range exportTx.Ins {
				verificableimport := fxs.FxCredential{Verifiable: cred}
				pChainUnsignedTx.Creds = append(pChainUnsignedTx.Creds, verificableimport.Verifiable)
			}

			signedBytes, err = platformvm.Codec.Marshal(CodecVersion, pChainUnsignedTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
			}

			pChainUnsignedTx.Initialize(unsignedBytes, signedBytes)

			hexstr2, err = formatting.EncodeWithChecksum(formatting.Hex, pChainUnsignedTx.Bytes())
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.HexEncodeError, err)
			}
		} else if originChain == "C" {
			submitTo = originChain
			txHexbytes, err := hex.DecodeString(tx.FullTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.HexDecodeError, err)
			}

			var exportTx evm.UnsignedExportTx
			_, err = evm.Codec.Unmarshal(txHexbytes, &exportTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
			}

			cChainUnsignedTx.UnsignedAtomicTx = &exportTx

			for _, _ = range cChainUnsignedTx.InputUTXOs() {
				verificableimport := fxs.FxCredential{Verifiable: cred}
				cChainUnsignedTx.Creds = append(cChainUnsignedTx.Creds, verificableimport.Verifiable)
			}

			signedBytes, err := evm.Codec.Marshal(EVMCodecVersion, cChainUnsignedTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
			}

			cChainUnsignedTx.Initialize(unsignedBytes, signedBytes)

			hexstr2, err = formatting.EncodeWithChecksum(formatting.Hex, cChainUnsignedTx.SignedBytes())
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.HexEncodeError, err)
			}

		}

	} else if txio == "import" {
		if targetChain == "P" {
			submitTo = targetChain
			var importTx ptxs.ImportTx

			_, err = platformvm.Codec.Unmarshal(unsignedBytes, &importTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
			}

			pChainUnsignedTx.Unsigned = &importTx

			for _, _ = range importTx.ImportedInputs {
				verificableimport := fxs.FxCredential{Verifiable: cred}
				pChainUnsignedTx.Creds = append(pChainUnsignedTx.Creds, verificableimport.Verifiable)
			}

			signedBytes, err = platformvm.Codec.Marshal(CodecVersion, pChainUnsignedTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
			}

			pChainUnsignedTx.Initialize(unsignedBytes, signedBytes)

			hexstr2, err = formatting.EncodeWithChecksum(formatting.Hex, pChainUnsignedTx.Bytes())
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.HexEncodeError, err)
			}
		} else if targetChain == "X" {
			submitTo = targetChain
			var importTx txs.ImportTx

			_, err = c.Unmarshal(unsignedBytes, &importTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
			}

			xChainUnsignedTx.Unsigned = &importTx

			for _, _ = range importTx.ImportedIns {
				xChainUnsignedTx.Creds = append(xChainUnsignedTx.Creds, &fxs.FxCredential{Verifiable: cred})
			}

			signedBytes, err = c.Marshal(CodecVersion, xChainUnsignedTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
			}

			xChainUnsignedTx.Initialize(unsignedBytes, signedBytes)

			hexstr2, err = formatting.EncodeWithChecksum(formatting.Hex, xChainUnsignedTx.Bytes())
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.HexEncodeError, err)
			}
		} else if targetChain == "C" {
			submitTo = targetChain
			txHexbytes, err := hex.DecodeString(tx.FullTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.HexDecodeError, err)
			}

			var importTx evm.UnsignedImportTx
			_, err = evm.Codec.Unmarshal(txHexbytes, &importTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
			}

			cChainUnsignedTx.UnsignedAtomicTx = &importTx

			for _, _ = range cChainUnsignedTx.InputUTXOs() {
				verificableimport := fxs.FxCredential{Verifiable: cred}
				cChainUnsignedTx.Creds = append(cChainUnsignedTx.Creds, verificableimport.Verifiable)
			}

			signedBytes, err := evm.Codec.Marshal(EVMCodecVersion, cChainUnsignedTx)
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
			}

			cChainUnsignedTx.Initialize(unsignedBytes, signedBytes)

			hexstr2, err = formatting.EncodeWithChecksum(formatting.Hex, cChainUnsignedTx.SignedBytes())
			if err != nil {
				return tx, errors.BuildAndLogErrorMsg(errors.HexEncodeError, err)
			}
		}
	}

	signatureJSON, _ := json.Marshal(signature)
	tx.FullTx = hex.EncodeToString(signedBytes)
	tx.Inputs[0].Signature = string(signatureJSON)
	tx.Status = l1common.TxSubmitted

	receipt, err := avaxAVMIssueTx(hexstr2, submitTo)
	if err != nil {
		return tx, fmt.Errorf("error issuing transaction: %w", err)
	}
	tx.Status = l1common.TxSubmitted
	tx.Receipt = receipt
	err = gateways.UpdateTx(messageHash, tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	log.Info("ExportTx Receipt:", receipt)

	return tx, nil
}

// avaxParseServiceAddresses prepares avalanche address from public key
func avaxParseServiceAddresses(pubKeyK ecdsa.PublicKey) (string, error) {
	var result string
	compressedBytes := SerializeUncompressed(&pubKeyK)
	pubKey, err := secp.ParsePubKey(compressedBytes)
	if err != nil {
		return result, err
	}
	fmt.Println("pubkey bytes method address:", pubKey.SerializeCompressed(), "bytes:", len(pubKey.SerializeCompressed()))
	pubKeyHash := SHARipemd(pubKey.SerializeCompressed())
	conv, err := bech32.ConvertBits(pubKeyHash, 8, 5, true)
	if err != nil {
		return result, err
	}
	result, err = bech32.Encode("fuji", conv)
	if err != nil {
		return result, err
	}

	return result, nil

}

// Helper function for converting between AVAX units
func nAvaxToAvax(val *big.Int) *big.Float {
	num := big.NewFloat(0).SetInt(val)
	dem := big.NewFloat(0).SetInt(big.NewInt(1000000000))
	return big.NewFloat(0).Quo(num, dem)
}

func AvaxTonAvax(val *big.Int) *big.Int {
	return new(big.Int).Mul(val, big.NewInt(1000000000))
}

// avaxAVMIssueTx provides single function for submitting signed transaction
// to quicknode insfrastructure.
func avaxAVMIssueTx(txPayload, blockchainId string) (string, error) {
	var result string
	var url, method string
	if blockchainId == "X" {
		url = fujiChains.XChain
		method = "avm.issueTx"
	} else if blockchainId == "P" {
		url = fujiChains.PChain
		method = "platform.issueTx"
	} else {
		url = fujiChains.CChain
		method = "avax.issueTx"
	}

	params := gateways.IssueTxParams{Tx: txPayload, Encoding: "hex"}
	request := gateways.QuicknodeRequest{Jsonrpc: "2.0", Id: 1, Method: method, Params: params}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	opts := &gateways.RequestParams{Method: gateways.MethodPost, Url: url, Body: bytes.NewBuffer(requestBytes)}
	req, err := http.NewRequest(opts.Method, opts.Url, opts.Body)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}

	resp, err := gateways.HttpRequest(req, opts)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.HttpRequestError, err)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.DecodeBodyError, err)
	}

	var quickNodeResponse gateways.QuicknodeResponse

	err = json.Unmarshal(respBody, &quickNodeResponse)
	if err != nil {
		return result, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	result = quickNodeResponse.Result.TxID
	return result, nil

}

// AvaxStake prepares staking transaction for the P-Chain
// The function builds the inputs and outputs needed to complete the transfer
// and organizes them into multiple inputs to collect multiple signatures from
// custody services
func AvaxStake(tx l1common.BasicTx, pubKey ecdsa.PublicKey) (l1common.BasicTx, error) {
	amount, err := strconv.ParseFloat(tx.Value, 64)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UnitConversionError, err)
	}

	nAmount := amount * 1000000000 //Convert to nAvax

	// Parse the from addresses
	fromAddrs, err := avaxParseServiceAddresses(pubKey)
	if err != nil {
		return tx, err
	}

	// Load user's UTXOs
	utxosDecoded, err := avaxGetUTXOs("P", "P", fromAddrs)
	if err != nil {
		return tx, err
	}

	// Parse the to the blockchain id short
	blockchainid, err := ids.FromString(chainIdMap["P"]) // Fuji ID
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	tx.Fee = float64(1000000)
	avaxAssetID, err := ids.FromString(avaxID) // AVAX aasset ID
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	ins := []*avax.TransferableInput{}
	ins, inputAmounts, err := prepareInputs(ins, utxosDecoded, uint64(nAmount), uint64(tx.Fee))
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.InputsError, err)
	}

	// Parse the to address
	fromShort, err := address.ParseToID("P" + avaxSeperator + fromAddrs)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	startTime := uint64(time.Now().Add(time.Second * 30).Unix())  // Move star by 30 second
	endTime := uint64(time.Now().Add(time.Hour * 24 * 30).Unix()) //hardcoding 1 month for now

	// Add the output to the staked outputs
	out1 := &avax.TransferableOutput{
		Asset: avax.Asset{ID: avaxAssetID},
		Out: &stakeable.LockOut{
			Locktime: endTime,
			TransferableOut: &secp256k1fx.TransferOutput{
				Amt: uint64(nAmount),
				OutputOwners: secp256k1fx.OutputOwners{
					Locktime:  endTime,
					Threshold: 1,
					Addrs:     []ids.ShortID{fromShort},
				},
			},
		},
	}

	//Output being locked into staking
	lockedOuts := []*avax.TransferableOutput{out1}

	out2 := &avax.TransferableOutput{
		Asset: avax.Asset{ID: avaxAssetID},
		Out: &secp256k1fx.TransferOutput{
			Amt: inputAmounts - uint64(nAmount) - uint64(tx.Fee),
			OutputOwners: secp256k1fx.OutputOwners{
				Locktime:  0,
				Threshold: 1,
				Addrs:     []ids.ShortID{fromShort},
			},
		},
	}

	//Remainder output not locked into staking
	unlockedOuts := []*avax.TransferableOutput{out2}

	nodeId, err := ids.NodeIDFromString(tx.Data)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.AddressError, err)
	}

	// Create the tx
	utx := &ptxs.AddDelegatorTx{
		BaseTx: ptxs.BaseTx{BaseTx: avax.BaseTx{
			NetworkID:    5,
			BlockchainID: blockchainid,
			Ins:          ins,
			Outs:         unlockedOuts,
		}},
		Validator: validator.Validator{
			NodeID: nodeId,
			Start:  startTime,
			End:    endTime,
			Wght:   uint64(nAmount),
		},
		Stake: lockedOuts,
		RewardsOwner: &secp256k1fx.OutputOwners{
			Locktime:  0,
			Threshold: 1,
			Addrs:     []ids.ShortID{fromShort},
		},
	}

	utxunsignedBytes, err := platformvm.Codec.Marshal(CodecVersion, utx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	unsignedtx := ptxs.Tx{Unsigned: utx}

	unsignedBytes, err := platformvm.Codec.Marshal(CodecVersion, &unsignedtx.Unsigned)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	txHex := hex.EncodeToString(utxunsignedBytes)
	tx.FullTx = txHex

	hash := hashing.ComputeHash256(unsignedBytes)
	tx.TxHash = "0x" + hex.EncodeToString(hash)
	tx.Inputs = []l1common.TxInputs{l1common.TxInputs{Hash: tx.TxHash, InputIndex: 0}}
	tx.Status = l1common.TxCreated

	err = gateways.WriteTx(tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	return tx, nil
}

// CompleteAvaxStakeTx function to complete submission of staking op
func CompleteAvaxStakeTx(messageHash string, signature l1common.EcdsaSignature) (l1common.BasicTx, error) {
	tx, err := gateways.ReadTx(messageHash, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.ReadTxError, err)
	}

	unsignedBytes, err := hex.DecodeString(tx.FullTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.HexDecodeError, err)
	}

	stakeUnsignedTx := ptxs.Tx{Unsigned: nil,
		Creds: []verify.Verifiable{}}

	sigbytes := sigToBytes(signature)

	cred := &secp256k1fx.Credential{
		Sigs: make([][65]byte, 1),
	}

	copy(cred.Sigs[0][:], sigbytes)

	var signedBytes []byte
	var hexstr2 string

	var stakeTx ptxs.AddDelegatorTx

	_, err = platformvm.Codec.Unmarshal(unsignedBytes, &stakeTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.UnmarshallError, err)
	}

	stakeUnsignedTx.Unsigned = &stakeTx

	for _, _ = range stakeTx.Ins {
		verificableimport := fxs.FxCredential{Verifiable: cred}
		stakeUnsignedTx.Creds = append(stakeUnsignedTx.Creds, verificableimport.Verifiable)
	}

	signedBytes, err = platformvm.Codec.Marshal(CodecVersion, stakeUnsignedTx)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.MarshallError, err)
	}

	stakeUnsignedTx.Initialize(unsignedBytes, signedBytes)

	hexstr2, err = formatting.EncodeWithChecksum(formatting.Hex, stakeUnsignedTx.Bytes())
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.HexEncodeError, err)
	}

	signatureJSON, _ := json.Marshal(signature)
	tx.FullTx = hex.EncodeToString(signedBytes)
	tx.Inputs[0].Signature = string(signatureJSON)
	tx.Status = l1common.TxSubmitted
	receipt, err := avaxAVMIssueTx(hexstr2, "P")
	if err != nil {
		return tx, fmt.Errorf("error issuing transaction: %w", err)
	}
	tx.Status = l1common.TxSubmitted
	tx.Receipt = receipt
	err = gateways.UpdateTx(messageHash, tx, gateways.DB.Transactions)
	if err != nil {
		return tx, errors.BuildAndLogErrorMsg(errors.WriteTxError, err)
	}

	log.Info("ExportTx Receipt:", receipt)

	return tx, nil
}

// sigToBytes conver signature to  R | S | V byte array
func sigToBytes(signature l1common.EcdsaSignature) []byte {
	sigbytes := append(signature.R.Bytes(), signature.S.Bytes()...)

	if signature.V > 0 {
		sigbytes = append(sigbytes, big.NewInt(int64(signature.V)).Bytes()...)
	} else if signature.V == 0 {
		empty := []byte{0}
		sigbytes = append(sigbytes, empty[0])
	}
	return sigbytes
}

// prepareInputs take utxos to prepare sorted inputs to satisfy transfer
func prepareInputs(ins []*avax.TransferableInput, utxosDecoded []avax.UTXO, nAmount, txFee uint64) ([]*avax.TransferableInput, uint64, error) {
	var inputAmounts uint64 = 0
	for _, utxo := range utxosDecoded {
		assetID := utxo.AssetID()

		out := utxo.Out

		var inputIntf verify.Verifiable

		switch out := out.(type) {
		case *secp256k1fx.MintOutput:
			inputIntf = verify.Verifiable(&secp256k1fx.TransferInput{
				Input: secp256k1fx.Input{
					SigIndices: []uint32{0},
				},
			})
		case *secp256k1fx.TransferOutput:
			inputAmounts += out.Amt
			inputIntf = verify.Verifiable(&secp256k1fx.TransferInput{
				Amt: out.Amt,
				Input: secp256k1fx.Input{
					SigIndices: []uint32{0},
				},
			})
		}

		input, ok := inputIntf.(avax.TransferableIn)
		if !ok {
			continue
		}

		// add the new input to the array
		ins = append(ins, &avax.TransferableInput{
			UTXOID: utxo.UTXOID,
			Asset:  avax.Asset{ID: assetID},
			In:     input,
		})

		if inputAmounts >= (uint64(nAmount) + txFee) {
			avax.SortTransferableInputs(ins)
			break
		}

	}
	return ins, inputAmounts, nil
}
