package helper

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func GetEnvString(key string, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}

	return defaultVal
}

func GetEnvInt(key string, defaultVal int) int {

	if valStr := os.Getenv(key); valStr != "" {
		val, err := strconv.Atoi(valStr)

		if err == nil {
			return val
		}

		log.Warnf("helpers.GetEnvInt: Environment variable '%s' is not a valid integer: %v. Using default: %d", key, err, defaultVal)
	}

	return defaultVal
}
