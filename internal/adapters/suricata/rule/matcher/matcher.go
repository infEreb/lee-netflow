package matcher

import (
	"fmt"
	"lee-netflow/internal/domain/rule"

	"github.com/google/gopacket"
)

type SuricataMatcher struct {
}

func New() *SuricataMatcher {
	return &SuricataMatcher{}
}

func (sm *SuricataMatcher) Match(pk gopacket.Packet, rule *rule.Rule) (matched bool, err error) {
	for _, els := range rule.GetAllElements() {
		for _, el := range els {
			_, matched := el.Match(pk)
			if !matched {
				return false, fmt.Errorf("Element %s dont matched for packet %s", el.String(), pk.String())
			}
		}
	}

	return true, nil
}