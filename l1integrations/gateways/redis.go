package gateways

import (
	"context"
	"finco/l1integration/common"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-redis/redis/v8"
	redisgo "github.com/gomodule/redigo/redis"
	"github.com/nitishm/go-rejson/v4"
)

// Application Constants
const (
	RedisDbPrefix    = "l1integration:"
	RedisStoragePath = "$"
)

// DB Keys
const (
	GasFeesDBKey = RedisDbPrefix + "gasfees:"
)

// to connect to the redis database and return redis client, redis json handler and context.
func RedisClient() (*redis.Client, *rejson.Handler, context.Context) {
	redisHost := common.GloabalENVVars.RedisHost
	if redisHost == "" {
		log.Error("Error Reading Redis Host")
	}
	redisPort := common.GloabalENVVars.RedisPort
	if redisPort == "" {
		log.Error("Error Reading Redis Port")
	}

	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)
	redisJson := rejson.NewReJSONHandler()
	// TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}
	op := &redis.Options{Addr: redisAddr, Password: "", WriteTimeout: 5 * time.Second}
	redisClient := redis.NewClient(op)

	ctx := context.Background()
	err := redisClient.Ping(ctx).Err()
	if err != nil {
		log.Error("Error Reading Redis Ping")
	}
	redisJson.SetGoRedisClient(redisClient)
	return redisClient, redisJson, ctx
}

// Store the json data to the redis db by id and data.
func JsonDataStorage(id string, data interface{}) (interface{}, error) {
	redisClient, redisJson, _ := RedisClient()
	defer redisClient.Close()
	res, err := redisJson.JSONSet(GasFeesDBKey+id, RedisStoragePath, data)
	return res, err
}

// Get the json data to the redis db by id.
func JsonDataGet(id string) ([]byte, error) {
	redisClient, redisJson, _ := RedisClient()
	defer redisClient.Close()
	res, err := redisJson.JSONGet(GasFeesDBKey+id, RedisStoragePath)
	if err != nil {
		return nil, err
	}
	resBytes, errBytes := redisgo.Bytes(res, err)
	if errBytes != nil {
		return nil, errBytes
	}
	return resBytes, nil
}
