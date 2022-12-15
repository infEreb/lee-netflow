package parser

import (
	"fmt"
	"lee-netflow/internal/adapters/suricata/rule/element/action"
	"lee-netflow/internal/adapters/suricata/rule/element/address"
	"lee-netflow/internal/adapters/suricata/rule/element/direction"
	"lee-netflow/internal/adapters/suricata/rule/element/option"
	"lee-netflow/internal/adapters/suricata/rule/element/port"
	"lee-netflow/internal/adapters/suricata/rule/element/protocol"
	"lee-netflow/internal/domain/rule"
	"regexp"
	"strings"
)

func New() *SuricataParser {
	return &SuricataParser{}
}

func AddAvailableAddressConstant(const_name string) error {
	return address.AddAvailable(const_name)
}
func AddValidAddressConstant(const_name string, const_value []string) error {
	return address.AddValid(const_name, const_value)
}

func AddAvailablePortConstant(const_name string) error {
	return port.AddAvailable(const_name)
}
func AddValidPortConstant(const_name string, const_value []string) error {
	return port.AddValid(const_name, const_value)
}

func (sp *SuricataParser) Parse(rule_text string) (*rule.Rule, error) {
	rule := rule.New()

	if strings.HasPrefix(rule_text, "# ") {
		rule.Disable()
	}
	rule_str := strings.TrimPrefix(rule_text, "# ")

	elements_re, _ := regexp.Compile(`(.*?) (.*?) (!?\$[A-Z,_]+|!?\[.*?\]|!?.*?) (!?\$[A-Z,_]+|!?\[.*?\]|!?.*?) (->|<-|<>) (!?\$[A-Z,_]+|!?\[.*?\]|!?.*?) (!?\$[A-Z,_]+|!?\[.*?\]|!?.*?) (\(.*?\))$`)
	elements := elements_re.FindStringSubmatch(rule_str)
	if elements == nil {
		return nil, fmt.Errorf("Bad rule format.")
	}
	if len(elements) != 9 {
		return nil, fmt.Errorf("Bad rule format.")
	}

	rule.AddElement(action.New(elements[1]))
	rule.AddElement(protocol.New(elements[2]))
	rule.AddElement(address.New(elements[3], SrcAddress))
	rule.AddElement(port.New(elements[4], SrcPort))
	rule.AddElement(direction.New(elements[5]))
	rule.AddElement(address.New(elements[6], DstAddress))
	rule.AddElement(port.New(elements[7], DstPort))

	opts_str := strings.TrimPrefix(elements[8], "(")
	opts_str = strings.TrimSuffix(opts_str, ")")
	opts_str = strings.Trim(opts_str, " ")

	if !strings.HasSuffix(opts_str, ";") {
		return nil, fmt.Errorf("Options must have ends with ';'")
	}
	opts_str = strings.TrimSuffix(opts_str, ";")

	opts := strings.Split(opts_str, ";")
	for _, opt := range opts {
		rule.AddElement(option.New(opt))
	}

	for _, elems := range rule.GetAllElements() {
		for _, elem := range elems {
			if !elem.IsValid() {
				return nil, fmt.Errorf("Field %s has invalid value - %s", elem.GetType().GetName(), elem.GetValue())
			}
			if !elem.IsAvailable() {
				return nil, fmt.Errorf("Field %s has unavailable value - %s", elem.GetType().GetName(), elem.GetValue())
			}
		}
	}
	
	return rule, nil
}