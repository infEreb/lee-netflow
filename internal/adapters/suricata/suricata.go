package suricata

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"lee-netflow/internal/adapters/suricata/rule/constants"
	"lee-netflow/internal/adapters/suricata/rule/element/address"
	"lee-netflow/internal/adapters/suricata/rule/element/constant"
	suricata_matcher "lee-netflow/internal/adapters/suricata/rule/matcher"
	suricata_parser "lee-netflow/internal/adapters/suricata/rule/parser"
	suricata_validator "lee-netflow/internal/adapters/suricata/rule/validator"
	"lee-netflow/internal/domain/rule/matcher"
	"lee-netflow/internal/domain/rule/parser"
	"lee-netflow/internal/domain/rule/validator"
)

type SuricataConfig struct {
	Addresses map[string]string `json:"addresses"`
	Ports map[string]string `json:"ports"`
}

type Suricata struct {
	parser suricata_parser.SuricataParser
	validator suricata_validator.SuricataValidator
	matcher suricata_matcher.SuricataMatcher
}

func New() *Suricata {
	return &Suricata{
		parser: *suricata_parser.New(),
		matcher: *suricata_matcher.New(),
		validator: *suricata_validator.New(),
	}
}

func (s *Suricata) GetParser() parser.Parser {
	return &s.parser
}

func (s *Suricata) GetValidator() validator.Validator {
	return &s.validator
}

func (s *Suricata) GetMatcher() matcher.Matcher {
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
		if !constants.IsConstant(key) {
			return fmt.Errorf("Expected formatted constant. Found %s", key)
		}

		// if its ipv4
		if constants.IsIPv4(value) {
			src_addr := constant.New(key, address.New(value, constants.SrcAddress))
			dst_addr := constant.New(key, address.New(value, constants.DstAddress))
			if err = s.validator.AddValid(src_addr); err != nil {
				return err
			}
			if err = s.validator.AddValid(dst_addr); err != nil {
				return err
			}
			if err = s.validator.AddAvailable(src_addr); err != nil {
				return err
			}
			if err = s.validator.AddAvailable(dst_addr); err != nil {
				return err
			}
		}

		if constants.IsGroup(value) {
			src_group, err := suricata_parser.ParseGroup(value, constants.SrcAddress)
			if err != nil {
				return err
			}
			dst_group, err := suricata_parser.ParseGroup(value, constants.DstAddress)
			if err != nil {
				return err
			}
			src_const_grp := constant.New(key, src_group)
			dst_const_grp := constant.New(key, dst_group)
			if err = s.validator.AddValid(src_const_grp); err != nil {
				return nil
			}
			if err = s.validator.AddValid(dst_const_grp); err != nil {
				return nil
			}
			if err = s.validator.AddAvailable(src_const_grp); err != nil {
				return nil
			}
			if err = s.validator.AddAvailable(dst_const_grp); err != nil {
				return nil
			}
		}
	}
	// for key, value := range conf_json.Ports {
	// 	if err = suricata_parser.AddValidPortConstant(key, []string{value}); err != nil {
	// 		return err
	// 	}
	// 	if err = suricata_parser.AddAvailablePortConstant(key); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

func (s *Suricata) GetInfo() string {
	return "Suricata System Info"
}

func (s *Suricata) GetRuleFormat() string {
	return "Action Protocol SrcAddress SrcPort Direction DstAddress DstPort Options"
}