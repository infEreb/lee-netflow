package parser

import (
	"fmt"
	"lee-netflow/internal/adapters/suricata/rule/constants"
	"lee-netflow/internal/adapters/suricata/rule/element/action"
	"lee-netflow/internal/adapters/suricata/rule/element/address"
	"lee-netflow/internal/adapters/suricata/rule/element/constant"
	"lee-netflow/internal/adapters/suricata/rule/element/direction"
	"lee-netflow/internal/adapters/suricata/rule/element/group"
	"lee-netflow/internal/adapters/suricata/rule/element/keyword"
	"lee-netflow/internal/adapters/suricata/rule/element/option"
	"lee-netflow/internal/adapters/suricata/rule/element/port"
	"lee-netflow/internal/adapters/suricata/rule/element/portrange"
	"lee-netflow/internal/adapters/suricata/rule/element/protocol"
	"lee-netflow/internal/domain/rule"
	"lee-netflow/internal/domain/rule/element"
	"lee-netflow/internal/domain/rule/parser"
	"lee-netflow/internal/domain/rule/validator"
	"regexp"
	"strings"
)

type SuricataParser struct {
}

func New() *SuricataParser {
	return &SuricataParser{}
}

// func AddAvailableAddressConstant(const_name string) error {
// 	return address.AddAvailable(const_name)
// }
// func AddValidAddressConstant(const_name string, const_value []string) error {
// 	return address.AddValid(const_name, const_value)
// }

// func AddAvailablePortConstant(const_name string) error {
// 	return port.AddAvailable(const_name)
// }
// func AddValidPortConstant(const_name string, const_value []string) error {
// 	return port.AddValid(const_name, const_value)
// }



func (sp *SuricataParser) Parse(rule_text string, rule_name string, valid validator.Validator) (ans *parser.ParserAnswer, err error) {
	s_rule := rule.New(rule_name, rule_text)

	if strings.HasPrefix(rule_text, "#") {
		s_rule.Disable()
	}
	rule_str := strings.TrimPrefix(rule_text, "#")
	for ; rule_str != strings.TrimPrefix(rule_str, " "); rule_str = strings.TrimPrefix(rule_str, " ") {
	}

	elements_re, _ := regexp.Compile(`(.*?) (.*?) (!?\[.*?\]|.*?) (!?\[.*?\]|.*?) (->|<-|<>) (!?\[.*?\]|.*?) (!?\[.*?\]|.*?) (\(.*?\))$`)
	elements := elements_re.FindStringSubmatch(rule_str)
	if elements == nil {
		if s_rule.IsDisabled() {
			return &parser.ParserAnswer{IsRule: false, Rule: nil}, fmt.Errorf("Not a rule. Just comment")
		}
		return &parser.ParserAnswer{IsRule: true, Rule: nil}, fmt.Errorf("Bad rule format: %s", rule_text)
	}
	if len(elements) != 9 {
		if s_rule.IsDisabled() {
			return &parser.ParserAnswer{IsRule: false, Rule: nil}, fmt.Errorf("Not a rule. Just comment")
		}
		return &parser.ParserAnswer{IsRule: true, Rule: nil}, fmt.Errorf("Bad rule format: %s", rule_text)
	}

	// action parse
	act, _ := ParseAction(elements[1])
	s_rule.AddElement(act, constants.ActionType)
	// protocol parse
	proto, _ := ParseProtocol(elements[2])
	s_rule.AddElement(proto, constants.ProtocolType)
	// parse src address
	src_addr, err := ParseAddress(elements[3], constants.SrcAddressType, valid.GetBaseValidator())
	if err != nil {
		return &parser.ParserAnswer{IsRule: true, Rule: nil}, fmt.Errorf("%s. Rule: %s", err.Error(), rule_str)
	}
	s_rule.AddElement(src_addr, constants.SrcAddressType)
	// parse src port
	src_port, err := ParsePort(elements[4], constants.SrcPortType, valid.GetBaseValidator())
	if err != nil {
		return &parser.ParserAnswer{IsRule: true, Rule: nil}, fmt.Errorf("%s. Rule: %s", err.Error(), rule_str)
	}
	s_rule.AddElement(src_port, constants.SrcPortType)
	// parse direction
	dir, err := ParseDirection(elements[5])
	s_rule.AddElement(dir, constants.DirectionType)
	// parse dst address
	dst_addr, err := ParseAddress(elements[6], constants.DstAddressType, valid.GetBaseValidator())
	if err != nil {
		return &parser.ParserAnswer{IsRule: true, Rule: nil}, fmt.Errorf("%s. Rule: %s", err.Error(), rule_str)
	}
	s_rule.AddElement(dst_addr, constants.DstAddressType)
	// parse src port
	dst_port, err := ParsePort(elements[7], constants.DstPortType, valid.GetBaseValidator())
	if err != nil {
		return &parser.ParserAnswer{IsRule: true, Rule: nil}, fmt.Errorf("%s. Rule: %s", err.Error(), rule_str)
	}
	s_rule.AddElement(dst_port, constants.DstPortType)

	opts_str := strings.TrimPrefix(elements[8], "(")
	opts_str = strings.TrimSuffix(opts_str, ")")
	// opts_str = strings.Replace(opts_str, " ", "", -1)

	if !strings.HasSuffix(opts_str, ";") {
		return nil, fmt.Errorf("Options must ends with ';'")
	}
	opts_str = strings.TrimSuffix(opts_str, ";")

	opts := strings.Split(opts_str, ";")
	for _, opt := range opts {
		s_rule.AddElement(option.New(opt), constants.OptionType)
	}

	// for _, elems := range rule.GetAllElements() {
	// 	for _, elem := range elems {
	// 		if !elem.IsValid() {
	// 			return nil, fmt.Errorf("Field %s has invalid value - %s", elem.GetType().GetName(), elem.GetValue())
	// 		}
	// 		if !elem.IsAvailable() {
	// 			return nil, fmt.Errorf("Field %s has unavailable value - %s", elem.GetType().GetName(), elem.GetValue())
	// 		}
	// 	}
	// }

	return &parser.ParserAnswer{IsRule: true, Rule: s_rule}, nil
}

// return element of correct type
func ParseElements(elem_str string, elem_type element.ElementType, valid *validator.BaseValidator) (element.Element, error) {
	if constants.IsConstant(elem_str) {
		el_temp := constant.New(elem_str, action.New("constant"))
		elems, err := valid.GetValidByType(constants.ConstantType)
		if err != nil {
			return nil, err
		}
		for _, el := range elems {
			cp_el := el.Clone()
			if cp_el.Compare(el_temp) {
				if constants.IsSrcType(elem_type) {
					cp_el.SetSrcType()
				}
				if constants.IsDstType(elem_type) {
					cp_el.SetDstType()
				}
				return cp_el, nil
			}
		}

		return nil, fmt.Errorf("Cannot find element %s with %s type as a valid element", elem_str, elem_type.GetName())
	}

	if constants.IsIPv4(elem_str) {
		return address.New(elem_str, elem_type), nil
	}

	if constants.IsPort(elem_str) {
		return port.New(elem_str, elem_type), nil
	}

	if constants.IsPortRange(elem_str) {
		pr := portrange.New(elem_str, [2]element.Element{})
		min_max := strings.Split(elem_str, ":")
		if min_max[0] == "" {
			min_max[0] = fmt.Sprint(constants.MIN_PORT)
		}
		if min_max[1] == "" {
			min_max[1] = fmt.Sprint(constants.MAX_PORT)
		}
		pr.SetRange([2]element.Element{
			port.New(min_max[0], elem_type),
			port.New(min_max[1], elem_type),
		})
		// eof_elem := false
		// elem := ""
		// l := len(elem_str)
		// for i := 0; i <= l; i++ {
		// 	ch := byte(' ')
		// 	if i != l {
		// 		ch = elem_str[i]
		// 	}
		// 	// if our element is port range
		// 	if eof_elem && strings.Contains(elem, ":") {
		// 		min_max := strings.Split(elem, ":")
		// 		if min_max[0] == "" {
		// 			min_max[0] = fmt.Sprint(constants.MIN_PORT)
		// 		}
		// 		if min_max[1] == "" {
		// 			min_max[1] = fmt.Sprint(constants.MAX_PORT)
		// 		}
		// 		pr.AddRange([2]element.Element{
		// 			port.New(min_max[0], elem_type), // min_max[0] = first port of range (for 1024:4096 is 1024)
		// 			port.New(min_max[1], elem_type), // min_max[1] = second port
		// 		})
		// 		elem = ""
		// 		eof_elem = false
		// 		continue
		// 	}
		// 	// if our element is just port
		// 	if eof_elem && !strings.Contains(elem, ":") {
		// 		pr.AddPort(port.New(elem, elem_type))
		// 		elem = ""
		// 		eof_elem = false
		// 		continue
		// 	}
			
		// 	if ch == '[' || ch == ']' || ch == ' ' {
		// 		continue
		// 	}
			
		// 	if ch == ',' {
		// 		eof_elem = true
		// 	}
		// 	if i == l-1 && !eof_elem {
		// 		eof_elem = true
		// 	}

		// 	elem += string(ch)
		// }
		return pr, nil
	}

	if constants.IsGroup(elem_str) {
		grp := group.New(elem_str)
		in_grp := 0
		elem := ""
		eof_elem := false

		for _, ch := range elem_str {

			if ch == '[' && in_grp == 0 {
				in_grp++
				continue
			}
			if ch == '[' && in_grp > 0 {
				in_grp++
				elem += string(ch)
				continue
			}
			// if we're inside more than 2nd or eq 2 group and char is ']'
			if ch == ']' && in_grp >= 2 { // [[[11, 12], 21], 31]
				in_grp--
				elem += string(ch)
				continue
			}
			// if we're inside 1st group and char is ']'
			if ch == ']' && in_grp == 1 {
				in_grp--
				eof_elem = true
			}
			// if we're inside 2nd group
			if in_grp > 1 {
				elem += string(ch)
				continue
			}
			if in_grp > 1 && ch == ' ' {
				elem += string(ch)
			}
			if in_grp == 1 && ch == ',' {
				eof_elem = true
			}
			if in_grp == 1 && ch == ' ' {
				continue
			}
			if in_grp == 1 && !eof_elem {
				elem += string(ch)
				continue
			}

			if eof_elem {
				p_elem, err := ParseElements(elem, elem_type, valid)
				if err != nil {
					return action.New("NULL"), err
				}
				grp.AddElement(p_elem)
				elem = ""
				eof_elem = false
				continue
			}
			// elem += string(ch)

		}
		return grp, nil
	}

	if constants.IsKeyword(elem_str) {
		return keyword.New(elem_str), nil
	}

	return action.New("NULL"), fmt.Errorf("Has doesnt matched any element: %s", elem_str)
}

func ParseAction(act_str string) (*action.Action, error) {
	return action.New(act_str), nil
}

func ParseProtocol(proto_str string) (*protocol.Protocol, error) {
	return protocol.New(proto_str), nil
}

func ParseAddress(addr_str string, addr_type element.ElementType, valid *validator.BaseValidator) (element.Element, error) {
	p_addr, err := ParseElements(addr_str, addr_type, valid)
	if err != nil {
		return nil, err
	}
	if !p_addr.GetType().Compare(constants.AddressType) &&
		!p_addr.GetType().Compare(constants.ConstantType) &&
		!p_addr.GetType().Compare(constants.GroupType) &&
		!p_addr.GetType().Compare(constants.KeywordType) {
		return nil, fmt.Errorf("Value %s is not an address, constant, keyword or group", addr_str)
	}
	return p_addr, nil
}

func ParsePort(port_str string, port_type element.ElementType, valid *validator.BaseValidator) (element.Element, error) {
	p_port, err := ParseElements(port_str, port_type, valid)
	if err != nil {
		return nil, err
	}
	if !p_port.GetType().Compare(constants.PortType) &&
		!p_port.GetType().Compare(constants.ConstantType) &&
		!p_port.GetType().Compare(constants.GroupType) &&
		!p_port.GetType().Compare(constants.PortRangeType) &&
		!p_port.GetType().Compare(constants.KeywordType) {
		return nil, fmt.Errorf("Value %s is not a port, constant, keyword, group or port range", port_str)
	}
	return p_port, err
}

func ParseConstant(const_str string, elem_type element.ElementType, valid *validator.BaseValidator) (element.Element, error) {
	p_const, err := ParseElements(const_str, elem_type, valid)
	if err != nil {
		return nil, err
	}
	return p_const, nil
}

func ParseGroup(group_str string, group_elem_type element.ElementType, valid *validator.BaseValidator) (grp element.Element, err error) {
	grp, err = ParseElements(group_str, group_elem_type, valid)
	if err != nil {
		return nil, err
	}
	return grp, nil
}

func ParseDirection(dir_str string) (*direction.Direction, error) {
	return direction.New(dir_str), nil
}
