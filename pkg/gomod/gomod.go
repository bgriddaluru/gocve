package gomod

import "github.com/bgriddaluru/gocve/pkg/utils/logger"

type GoMod struct {
	logger *logger.Logger
}

func NewClient(logger *logger.Logger) *GoMod {
	return &GoMod{
		logger: logger,
	}
}
