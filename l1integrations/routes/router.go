package routes

import (
	"finco/l1integration/operations"

	"github.com/gin-gonic/gin"
)

func RouteHandler(routeEngine *gin.Engine) {

	// Helper route for cron job to update the gas fees for each chain
	routeEngine.GET("/", HandlerWrap(operations.GetAllChainsFees))

	router := routeEngine.Group("/api")

	//postTx api for creating a new transaction that transfer funds from one account to another.
	// saves txs in mongoDB and return tx hash that needs to be signed according to blockchain spec
	router.POST("/postTx", HandleAsCreateTx(operations.PostTx))

	//remoteTx api for creating transactions originating remotely
	router.POST("/remoteTx", HandleAsCreateTx(operations.RemoteTx))

	//stakeTx api for creating a new transaction that will deposit token into staking contract.
	// saves txs in mongoDB and return tx hash that needs to be signed according to blockchain spec
	router.POST("/stakeTx", HandleAsCreateTx(operations.StakeTx))

	//complete postTx updates previously created transaction and includes the signature
	// and submit transaction to infrastructure provider depending on token type
	router.PUT("/postTx", HandleAsCompleteTx(operations.CompleteTx))

	//crossChainTx api for creating a new transaction that transfer funds for the same account holder
	// from one chain to another. e.g. Avalanche cross chains
	//saves txs in mongoDB and return tx hash that needs to be signed according to blockchain spec
	router.POST("/api/crossChainTx", HandleAsCreateTx(operations.CrossChainTx))

	//crossChainTx api for creating a new transaction that transfer funds for the same account holder
	// from one chain to another. e.g. Avalanche cross chains
	//saves txs in mongoDB and return tx hash that needs to be signed according to blockchain spec
	router.PUT("/crossChainTx", HandleAsCompleteTx(operations.CompleteCrossChainTx))

	//complete stakeTx updates previously created transaction and includes the signature
	// and submit transaction to infrastructure provider depending on token type
	router.PUT("/stakeTx", HandleAsCompleteTx(operations.CompleteStakeTx))

	//getAddress provides api endpoint for saving key share data from a customer for
	// a specific blockchain that uses ecdsa signing algorithm
	router.GET("/getAddress/:userId/:blockchainId/:accountName", HandlerWrap(operations.GetAddress))

	router.GET("/GetAllChainsFees", HandlerWrap(operations.GetAllChainsFees))

	router.GET("/uniQuote/:blockchainId/:tokenInId/:tokenOutId/:amount", HandlerWrap(operations.UniQuote))

	router.GET("/oneInchQuote/:blockchainId/:tokenInId/:tokenOutId/:amount", HandlerWrap(operations.OneInchQuote))

	router.GET("/quote/:blockchainId/:tokenInId/:tokenOutId/:amount", HandlerWrap(operations.Quote))
}
