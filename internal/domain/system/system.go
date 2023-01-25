package system

import (
	"lee-netflow/internal/domain/rule/matcher"
	"lee-netflow/internal/domain/rule/parser"
	"lee-netflow/internal/domain/rule/validator"
	"log"
)

type System interface {
	// Main logic of configure system
	Configure(config_path string) error
	// Main logic of system work
	Run() error
	// Loggers
	InfoLog() *log.Logger
	DebugLog() *log.Logger
	ErrorLog() *log.Logger
	// Returns info about system
	GetInfo() string
}

type RuleFormatSystem interface {
	System
	GetParser() parser.Parser
	GetValidator() validator.Validator
	GetMatcher() matcher.Matcher

	// Rule format of this system
	GetRuleFormat() string
}