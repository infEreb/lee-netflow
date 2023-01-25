package parser

import (
	"lee-netflow/internal/domain/rule"
)

type ParserAnswer struct {
	IsRule bool
	Rule   *rule.Rule
}

// Interface of rule parser
type Parser interface {
	// Parses rule with
	Parse(string, string) (*ParserAnswer, error)
}
