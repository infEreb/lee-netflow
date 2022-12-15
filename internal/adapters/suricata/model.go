package suricata

import (
	"lee-netflow/internal/adapters/suricata/rule/matcher"
	"lee-netflow/internal/adapters/suricata/rule/parser"
)

type SuricataConfig struct {
	Addresses map[string]string `json:"addresses"`
	Ports map[string]string `json:"ports"`
}

type Suricata struct {
	parser parser.SuricataParser
	matcher matcher.SuricataMatcher
}