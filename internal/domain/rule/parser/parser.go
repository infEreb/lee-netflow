package parser

import (
	"lee-netflow/internal/domain/rule"
	"lee-netflow/internal/domain/rule/validator"
)

type ParserAnswer struct {
	IsRule bool
	Rule   *rule.Rule
}

// Interface of rule parser
type Parser interface {
	// Parses rule with rule name
	// 1st - rule text
	// 2nd - rule name
	// 3rd - rule validator
	Parse(string, string, validator.Validator) (*ParserAnswer, error)
}
