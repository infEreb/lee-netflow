package address

import (
	"lee-netflow/internal/domain/rule/element"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

var (
	validAddressesConstants = map[string][]string{
		"any": {
			"0.0.0.0/0",
		},
	}
	availableAddressesConstants = []string{
		"any",
	}
)

// Address type of suricata rules
type AddressType struct {
	name string
}

// Returns name of AddressType type
func (at *AddressType) GetName() string {
	return at.name
}

// Sets name of AddressType type
func (at *AddressType) SetName(addr_type_name string) {
	at.name = addr_type_name
}

func (at *AddressType) Compare(b_at element.ElementType) bool {
	s_at, ok := b_at.(*AddressType)
	if !ok {
		return false
	}
	return at.name == s_at.GetName()
}

// Type for source address AddressType of rule
type SrcAddressType struct {
	AddressType
}

// Type for destination address AddressType of rule
type DstAddressType struct {
	AddressType
}

// Address rule element
type Address struct {
	value       string
	is_negative bool
	addr_type   element.ElementType
}

// Creates new Address rule element of addr_type AddressType
func New(value string, addr_type element.ElementType) *Address {
	// if value is negative
	neg := false
	if value[0] == '!' {
		value = strings.TrimPrefix(value, "!")
		neg = true
	}

	return &Address{
		value:       value,
		is_negative: neg,
		addr_type:   addr_type,
	}
}

// Returns new object of AddressType type
func GetAddressType() *AddressType {
	return &AddressType{
		name: "Address",
	}
}

// Returns new object of SrcAddressType type
func GetSrcAddressType() *SrcAddressType {
	return &SrcAddressType{
		AddressType: AddressType{
			name: "SrcAddress",
		},
	}
}

// Returns new object of DstAddressType type
func GetDstAddressType() *DstAddressType {
	return &DstAddressType{
		AddressType: AddressType{
			name: "DstAddress",
		},
	}
}

func (a *Address) GetValue() string {
	return a.value
}

func (a *Address) SetValue(value string) {
	a.value = value
}

func (a *Address) GetType() element.ElementType {
	return a.addr_type
}

func (a *Address) SetType(addr_type element.ElementType) {
	a.addr_type = addr_type
}

func (a *Address) Compare(b_a element.Element) bool {
	s_a, ok := b_a.(*Address)
	if !ok {
		return false
	}
	return a.value == s_a.value
}

// Sets negative value for address (that means we have '! char with this one)
func (a *Address) Negative() {
	a.is_negative = true
}
func (a *Address) IsNegavite() bool {
	return a.is_negative
}

func IsConstant(addr_const string) bool {
	addr_re, _ := regexp.MatchString(`!?\$[A-Z,_]+|any`, addr_const)
	return addr_re
}
func IsAddressIPv4(addr_str string) bool {
	addr_check := func(addr_str string) bool {
		addr_str = strings.TrimPrefix(addr_str, "!")
		octs := strings.Split(addr_str, ".")

		if len(octs) != 4 {
			return false
		}

		for _, oct := range octs {
			n, err := strconv.Atoi(oct)
			if err != nil {
				return false
			}

			if n < 0 || n > 255 {
				return false
			}
		}
		return true
	}

	addr_prefix := strings.Split(addr_str, "/")

	if len(addr_prefix) == 1 {
		return addr_check(addr_prefix[0])
	}

	if len(addr_prefix) == 2 {
		prefix_n, err := strconv.Atoi(addr_prefix[1])
		if err != nil {
			return false
		}
		if prefix_n < 0 || prefix_n > 32 {
			return false
		}
		return addr_check(addr_prefix[0])
	}

	return false
}
func IsGroup(addr_group string) bool {
	addr_re, _ := regexp.MatchString(`^!?\[.*?\]`, addr_group)
	return addr_re
}
func CheckValidElem(addr_elem string) bool {
	if IsConstant(addr_elem) {
		const_str := strings.TrimPrefix(addr_elem, "!")
		if _, has := validAddressesConstants[const_str]; has {
			return true
		}
		return false
	}
	if IsAddressIPv4(addr_elem) {
		return true
	}
	if IsGroup(addr_elem) {
		group_str := strings.TrimPrefix(addr_elem, "!")
		group_str = strings.TrimPrefix(group_str, "[")
		group_str = strings.TrimSuffix(group_str, "]")
		group_elems := strings.Split(strings.Replace(group_str, " ", "", -1), ",")
		for _, elem := range group_elems {
			if !CheckValidElem(elem) {
				return false
			}
		}
		return true
	}
	// cannot be other type
	return false
}

func CheckAvailableElem(addr_elem string) bool {
	if IsConstant(addr_elem) {
		const_str := strings.TrimPrefix(addr_elem, "!")
		if slices.Contains(availableAddressesConstants, const_str) {
			return true
		}
		return false
	}
	if IsAddressIPv4(addr_elem) {
		return true
	}
	if IsGroup(addr_elem) {
		group_str := strings.Trim(addr_elem, "[]")
		group_elems := strings.Split(strings.Replace(group_str, " ", "", -1), ",")
		for _, elem := range group_elems {
			if !CheckAvailableElem(elem) {
				return false
			}
		}
		return true
	}
	// cannot be other type
	return true
}
