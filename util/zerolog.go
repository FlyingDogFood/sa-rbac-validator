package util

import "github.com/rs/zerolog"

func IsLogLevelHigher(logger zerolog.Logger, compareLogLevel zerolog.Level) bool {
	return logger.GetLevel() <= compareLogLevel
}