package common

import (
	flowErrors "bitbucket.org/carsonliving/flow.packages.errors"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
)

/*
Usage Example

	type GetResidentTransactionsPayload struct {
		PropertyId string `uri:"propertyID" binding:"required,alphanum"`
		TenantId   string `uri:"tenantID" binding:"required,alphanum"`
	}

route.GET("/transactions/:propertyID/:tenantID",

	client.ValidateInput[models.GetResidentTransactionsPayload](),
	yardi.GetYardiTransactions,

)

input := client.GetInput[models.GetResidentTransactionsPayload](c)
payload := fmt.Sprintf(GetActiveChargesPayload, CredentialsPayload, input.PropertyID, input.TenantID)

The list of built-in validators can found at
https://github.com/go-playground/validator
*/
func ValidateInput[InputEntityType any]() func(*gin.Context) {
	return func(c *gin.Context) {
		var input InputEntityType

		err := c.ShouldBindJSON(&input)
		if err != nil {
			err = c.ShouldBindUri(&input)
			if err != nil {
				err = c.ShouldBindQuery(&input)
				if err != nil {
					SendErrorResponse(c, Exception{
						flowErrors.StatusBadRequest,
						flowErrors.ErrorTypeMap[flowErrors.ValidationErrorCode],
						err.Error()})
					return
				}
			}
		}

		c.Set("iEntity", input)

		c.Next()
	}
}

func SendErrorResponse(c *gin.Context, err Exception) {
	log.Errorf("Sending error response %v", err)
	c.AbortWithStatusJSON(err.Code, gin.H{
		"status":  false,
		"message": err.Message,
		"type":    err.ErrorType})
}

func SendResponse[OutputObjectType any](c *gin.Context, obj OutputObjectType) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.JSON(flowErrors.StatusOK, gin.H{
		"status": true,
		"result": obj,
	})
}

func GetInput[BodyType any](c *gin.Context) BodyType {
	return c.MustGet("iEntity").(BodyType)
}

// CORSMiddleware to apply server middleware for CORS
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func EnsureLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

func SendResponseStandard(c *gin.Context, obj interface{}) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.JSON(flowErrors.StatusOK, gin.H{
		"status": true,
		"result": obj,
	})
}

func WriteErrorResponse(statusCode int, message string, w http.ResponseWriter) {
	log.Error(message)
	// @TODO: need to integration flow error library to send valid type and message.
	errorResponse := ApiError{
		Status: false,
		Err: ErrorDetails{
			Type:    flowErrors.ErrorTypeMap[statusCode],
			Message: message,
		},
	}
	respJson, errRespJson := json.Marshal(errorResponse)
	if errRespJson != nil {
		WriteErrorResponse(flowErrors.JsonMarshalErrorCode, errRespJson.Error(), w)
		return
	}

	WriteCustomResponse(statusCode, respJson, w) //Returning 200 since error code is wrapped into response
}

// to write custom response to the request
func WriteCustomResponse(code int, res []byte, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	WriteRawResponse(code, res, w)
}

// to validate the response body and write raw response from 3rd party API
func ValidateAndWriteResponse(resp interface{}, err error, w http.ResponseWriter) {
	if err != nil {
		WriteErrorResponse(http.StatusBadRequest, err.Error(), w)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	successResponse := ApiSuccess{
		Status: true,
		Result: resp,
	}

	successResponseBytes, err := json.Marshal(successResponse)
	if err != nil {
		WriteErrorResponse(http.StatusBadRequest, err.Error(), w)
		return
	}

	WriteRawResponse(http.StatusCreated, successResponseBytes, w)
}

func WriteResponse(code int, res interface{}, w http.ResponseWriter) {
	if res == nil {
		w.Header().Set("Content-Type", "application/json")
		WriteRawResponse(code, []byte{}, w)
		return
	}
	b, err := json.Marshal(res)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Marshal JSON response failed, error=%q\n", err.Error())
	} else {
		w.Header().Set("Content-Type", "application/json")
		WriteRawResponse(code, b, w)
	}
}

func WriteRawResponse(code int, res []byte, w http.ResponseWriter) {
	w.WriteHeader(code)
	w.Write(res)
}
