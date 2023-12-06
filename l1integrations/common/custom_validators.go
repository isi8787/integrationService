package common

import (
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"os"
)

func validateMongoId(fl validator.FieldLevel) bool {
	_, err := primitive.ObjectIDFromHex(fl.Field().String())
	return err == nil
}

func SetupCustomValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		err := v.RegisterValidation("mongodb_object_id", validateMongoId)
		if err != nil {
			ForceExit("Failed to init custom validator")
		}
	}
}

func ForceExit(v interface{}) {
	log.Error(v)
	os.Exit(1)
}
