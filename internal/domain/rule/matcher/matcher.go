package matcher

import (
	"lee-netflow/internal/domain/rule"

	"github.com/google/gopacket"
)

// Interface for rule matcher
type Matcher interface {
	// Matches rule with packet and returns
	// matched result with error if has one 
	Match(gopacket.Packet, *rule.Rule) (bool, error)
}