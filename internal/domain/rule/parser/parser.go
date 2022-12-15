package parser

import (
	"lee-netflow/internal/domain/rule"
)

// Interface of rule parser
type Parser interface {
	// Parses rule with
	Parse(string) (*rule.Rule, error)
}
