package constants

import (
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
	"lee-netflow/internal/domain/rule/element"
	"regexp"
	"strconv"
	"strings"
)

// suricata types constants
var (
	ActionType element.ElementType = action.GetActionType()
	ProtocolType element.ElementType = protocol.GetProtocolType()
	
	AddressType element.ElementType = address.GetAddressType()
	SrcAddressType element.ElementType = address.GetSrcAddressType()
	DstAddressType element.ElementType = address.GetDstAddressType()
	
	PortType element.ElementType = port.GetPortType()
	SrcPortType element.ElementType = port.GetSrcPortType()
	DstPortType element.ElementType = port.GetDstPortType()

	PortRangeType element.ElementType = portrange.GetPortRangeType()
	SrcPortRangeType element.ElementType = portrange.GetSrcPortRangeType()
	DstPortRangeType element.ElementType = portrange.GetDstPortRangeType()
	
	DirectionType element.ElementType = direction.GetDirectionType()
	OptionType element.ElementType = option.GetOptionType()
	
	ConstantType element.ElementType = constant.GetConstantType()
	SrcConstantType element.ElementType = constant.GetSrcConstantType()
	DstConstantType element.ElementType = constant.GetDstConstantType()

	KeywordType element.ElementType = keyword.GetKeywordType()
	SrcKeywordType element.ElementType = keyword.GetSrcKeywordType()
	DstKeywordType element.ElementType = keyword.GetDstKeywordType()

	GroupType element.ElementType = group.GetGroupType()
	SrcGroupType element.ElementType = group.GetSrcGroupType()
	DstGroupType element.ElementType = group.GetDstGroupType()
)

const (
	RE_CONSTANT = `^(!?\$[A-Z,_]+)$`
	RE_KEYWORD = `^any$`
	RE_GROUP = `^!?\[.*?(,\s?.*?){1,}\]$`
	RE_PORT_RANGE_NEW = `^!?(\d{1,5}:\d{0,5}|\d{0,5}:\d{1,5})$`
	RE_PORT_RANGE = `^!?(\[(!?\d{1,5}|!?(\d{0,5}:\s?\d{1,5}|\d{1,5}:\s?\d{0,5}))(,\s?((!?\d{1,5})|(!?(\d{0,5}:\s?\d{1,5}|\d{1,5}:\s?\d{0,5}))))?\]|(\d{0,5}:\d{1,5}|\d{1,5}:\d{0,5}))$`
	RE_PORT = `^!?\d{1,5}$`
	RE_IPV4 = `^!?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?`

	MIN_PORT = 0
	MAX_PORT = 65535
)

func IsKeyword(keyword string) bool {
	matched, _ := regexp.MatchString(RE_KEYWORD, keyword)
	return matched
}

func IsConstant(const_str string) bool {
	matched, _ := regexp.MatchString(RE_CONSTANT, const_str)
	return matched
}

func IsGroup(group_str string) bool {
	matched, _ := regexp.MatchString(RE_GROUP, group_str)
	return matched && !IsPortRange(group_str)
}

func IsPortRange(range_str string) bool {
	matched, _ := regexp.MatchString(RE_PORT_RANGE_NEW, range_str)
	return matched
}

func IsPort(port_str string) bool {
	matched, _ := regexp.MatchString(RE_PORT, port_str)
	return matched
}

func IsIPv4(ipv4_str string) bool {
	matched, _ := regexp.MatchString(RE_IPV4, ipv4_str)
	if !matched {
		return false
	}

	ipv4_str = strings.TrimPrefix(ipv4_str, "!")

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

func IsSrcType(src_el element.ElementType) bool {
	return src_el.Compare(SrcAddressType) ||
		src_el.Compare(SrcPortType) ||
		src_el.Compare(SrcConstantType) ||
		src_el.Compare(SrcKeywordType) ||
		src_el.Compare(SrcGroupType) ||
		src_el.Compare(SrcPortRangeType)
}
func IsDstType(dst_el element.ElementType) bool {
	return dst_el.Compare(DstAddressType) ||
		dst_el.Compare(DstPortType) ||
		dst_el.Compare(DstConstantType) ||
		dst_el.Compare(DstKeywordType) ||
		dst_el.Compare(DstGroupType) ||
		dst_el.Compare(DstPortRangeType)
}