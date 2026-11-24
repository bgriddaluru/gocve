package logger

import (
	"github.com/fatih/color"
)

var (
	infoColor  = color.New(color.FgCyan)
	errorColor = color.New(color.FgRed)
	debugColor = color.New(color.FgGreen)
)

type Logger struct {
	DebugMode bool
}

func NewLogger(debugMode bool) *Logger {
	return &Logger{
		DebugMode: debugMode,
	}
}

func (l *Logger) Info(args ...any) {
	infoColor.Println(args...)
}

func (l *Logger) Error(args ...any) {
	errorColor.Println(args...)
}

func (l *Logger) Debug(args ...any) {
	if l.DebugMode {
		debugColor.Println(args...)
	}
}
