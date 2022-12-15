package suricata

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	suricata_matcher "lee-netflow/internal/adapters/suricata/rule/matcher"
	suricata_parser "lee-netflow/internal/adapters/suricata/rule/parser"
	"lee-netflow/internal/domain/rule/matcher"
	"lee-netflow/internal/domain/rule/parser"
)

func New() *Suricata {
	return &Suricata{
		parser: *suricata_parser.New(),
		matcher: *suricata_matcher.New(),
	}
}

func (s *Suricata) GetParser() parser.IParser {
	return &s.parser
}
func (s *Suricata) GetMatcher() matcher.IMatcher {
	return &s.matcher
}
func (s *Suricata) Configure(config_path string) error {
	conf_bytes, err := ioutil.ReadFile(config_path)
	if err != nil {
		return err
	}

	conf_json := SuricataConfig{}
	err = json.Unmarshal(conf_bytes, &conf_json)
	if err != nil {
		return err
	}

	if conf_json.Addresses == nil || conf_json.Ports == nil {
		return fmt.Errorf("Some troubles with parsing 'addresses' or 'ports' fields.")
	}

	for key, value := range conf_json.Addresses {
		if err = suricata_parser.AddValidAddressConstant(key, []string{value}); err != nil {
			return err
		}
		if err = suricata_parser.AddAvailableAddressConstant(key); err != nil {
			return err
		}
	}
	for key, value := range conf_json.Ports {
		if err = suricata_parser.AddValidPortConstant(key, []string{value}); err != nil {
			return err
		}
		if err = suricata_parser.AddAvailablePortConstant(key); err != nil {
			return err
		}
	}

	return nil
} 
func (s *Suricata) GetInfo() string {
	return "Suricata System Info"
}
func (s *Suricata) GetRuleFormat() string {
	return "Action Protocol SrcAddress SrcPort Direction DstAddress DstPort Options"
}