package main

import (
	"context"

	"finco/l1integration/common"
	"finco/l1integration/routes"
	"fmt"
	"net/http"

	"bitbucket.org/carsonliving/flowsdk"
	"bitbucket.org/carsonliving/flowsdk/integrations/flowgin"
	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"

	"github.com/gin-gonic/gin"
)

/*
func main() {

	listenAddress := ":" + common.L1Configurations.Server.Port
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		listenAddress = ":" + val
	}

	log.Info("Service Started on Port ", listenAddress)

	err := http.ListenAndServe(listenAddress, handlers.CORS(
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "PATCH", "DELETE"}),
		handlers.AllowedHeaders([]string{"Accept", "Accept-Language", "Content-Type", "Content-Language", "Origin"}),
	)(operations.NewRouter()),
	)
	if err != nil {
		log.Error(err)
	}
}
*/

var ginLambda *ginadapter.GinLambda

// setup complete app routers
func setupRouter() *gin.Engine {

	router := gin.Default()

	common.SetupCustomValidators()

	routes.RouteHandler(router)

	router.Use(common.CORSMiddleware())

	router.Use(flowgin.Middleware())

	return router
}

func main() {

	flowsdk.InitWithConfig(flowsdk.Config{
		ApplicationName: "L1 Integration Server",
		Environment:     "development",
	})

	if common.GloabalENVVars.GinMode == "release" {
		fmt.Println("running aws lambda in aws")
		g := setupRouter()
		ginLambda = ginadapter.New(g)
		lambda.Start(AWSHandler)
	} else {
		listenAddress := ":" + common.L1Configurations.Server.Port
		log.Info(fmt.Sprintf("** Service Started on Port %s **", listenAddress))
		log.Fatal(http.ListenAndServe(listenAddress, setupRouter()))
	}
}

func AWSHandler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return ginLambda.ProxyWithContext(ctx, request)
}
