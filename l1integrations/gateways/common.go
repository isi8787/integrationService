package gateways

import (
	"finco/l1integration/common"

	flow_aws_kms "bitbucket.org/carsonliving/aws-kms-client"
	ubiquity "gitlab.com/Blockdaemon/ubiquity/ubiquity-go-client/v1/pkg/client"
)

// MongoDB Client instance
var DB *common.Database = ConnectDB()

// AWS KSM Client instance
var KSM flow_aws_kms.KMSClient = KSMClient()

// Blockdaemon Client
var BD *ubiquity.APIClient = BlockDaemonConnect()
