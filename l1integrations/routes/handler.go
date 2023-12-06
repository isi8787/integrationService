package routes

import (
	"finco/l1integration/common"
	"finco/l1integration/errors"
	"finco/l1integration/gateways"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

// Validate createTX requests by account record
func HandleAsCreateTx(f func(c *gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Request.Header.Get("userId")
		var tx common.BasicTx
		err := c.ShouldBindBodyWith(&tx, binding.JSON)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.DecodeBodyError, err)), c.Writer)
			return
		}

		if userId != tx.UserId {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ClientUserIdEror, err)), c.Writer)
			return
		}

		accountRecords, err := gateways.ReadAccountRecords(tx.UserId, tx.BlockchainId, gateways.DB.AccountRecords)

		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadingAccountRecordError, err)), c.Writer)
		}

		if len(accountRecords) == 0 {
			err = gateways.CreateAccountRecord(tx.UserId, tx.BlockchainId, tx.AccountName, gateways.DB.AccountRecords)
			if err != nil {
				common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.InsertAccountRecordError, err)), c.Writer)
			}
		}

		f(c)
	}
}

// Validate completeTx by txHash and account record
func HandleAsCompleteTx(f func(c *gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Request.Header.Get("userId")
		var txInput common.TxSignedInputs
		err := c.ShouldBindBodyWith(&txInput, binding.JSON)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.DecodeBodyError, err)), c.Writer)
			return
		}

		if len(txInput.Inputs) == 0 || txInput.Inputs[0].Hash == "" || txInput.Inputs[0].Signature == "" {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.EmptyInputsError, err)), c.Writer)
			return
		}

		idHash := c.Request.URL.Query().Get("idHash")
		if idHash == "" {
			idHash = txInput.Inputs[0].Hash
		}

		tx, err := gateways.ReadTx(idHash, gateways.DB.Transactions)
		if err != nil {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ReadTxError, err)), c.Writer)
			return
		}

		if userId != tx.UserId {
			common.WriteErrorResponse(http.StatusBadRequest, fmt.Sprintf("%s", errors.BuildAndLogErrorMsg(errors.ClientUserIdEror, err)), c.Writer)
			return
		}

		f(c)
	}
}

// Validate a request
func HandlerWrap(f func(c *gin.Context)) gin.HandlerFunc {

	return func(c *gin.Context) {
		f(c)
	}
}
