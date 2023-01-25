package constants

import (
	"lee-netflow/internal/adapters/suricata/rule/element/action"
	"lee-netflow/internal/adapters/suricata/rule/element/address"
	"lee-netflow/internal/adapters/suricata/rule/element/constant"
	"lee-netflow/internal/adapters/suricata/rule/element/direction"
	"lee-netflow/internal/adapters/suricata/rule/element/option"
	"lee-netflow/internal/adapters/suricata/rule/element/port"
	"lee-netflow/internal/adapters/suricata/rule/element/protocol"
	"lee-netflow/internal/domain/rule/element"
	"regexp"
	"strconv"
	"strings"
)

// suricata types constants
var (
	ActionType element.ElementType = action.GetActionType()
	ProtocolType element.ElementType = protocol.GetProtocolType()
	SrcAddressType element.ElementType = address.GetSrcAddressType()
	SrcPortType element.ElementType = port.GetSrcPortType()
	DirectionType element.ElementType = direction.GetDirectionType()
	DstAddressType element.ElementType = address.GetDstAddressType()
	DstPortType element.ElementType = port.GetDstPortType()
	OptionType element.ElementType = option.GetOptionType()
	
	AddressType element.ElementType = address.GetAddressType()
	ConstantType element.ElementType = constant.GetConstantType()
)

const (
	RE_Constant = `^!?\$[A-Z,_]+$`
	RE_Group = `^!?\[.*?(,\s?.*?){1,}\]$`
	RE_PortRange = `^!?\[(!?\d{1,5}|!?\d{1,5}:\s?!?\d{1,5})(,\s?((!?\d{1,5})|(!?\d{1,5}:\s?!?\d{1,5})))?\]$`
	RE_Port = `^!?\d{1,5}$`
	RE_IPv4 = `^!?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?`
)

func IsConstant(const_str string) bool {
	matched, _ := regexp.MatchString(RE_Constant, const_str)
	return matched
}

func IsGroup(group_str string) bool {
	matched, _ := regexp.MatchString(RE_Group, group_str)
	return matched && !IsPortRange(group_str)
}

func IsPortRange(range_str string) bool {
	matched, _ := regexp.MatchString(RE_PortRange, range_str)
	return matched
}

func IsPort(port_str string) bool {
	matched, _ := regexp.MatchString(RE_Port, port_str)
	return matched
}

func IsIPv4(ipv4_str string) bool {
	matched, _ := regexp.MatchString(RE_IPv4, ipv4_str)
	if !matched {
		return false
	}

	check_ip := func(ip_str string) bool {
		ips_elems := strings.Split(ip_str, ".")
		if len(ips_elems) != 4 {
			return false
		}
		for _, ip_elem := range ips_elems {
			elem, err := strconv.Atoi(ip_elem)
			if err != nil {
				return false
			}
			if elem < 0 || elem > 255 {
				return false
			}
		}
		return true
	}
	chek_mask := func(mask_str string) bool {
		mask_num, err := strconv.Atoi(mask_str)
		if err != nil {
			return false
		}
		if mask_num < 0 || mask_num > 32 {
			return false
		}
		return true
	}

	ip_mask := strings.Split(ipv4_str, "/")
	if len(ip_mask) == 1 {
		return check_ip(ip_mask[0])
	}
	if len(ip_mask) == 2 {
		return check_ip(ip_mask[0]) && chek_mask(ip_mask[1])
	}
	return false
}