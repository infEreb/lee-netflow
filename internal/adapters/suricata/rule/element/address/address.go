package address

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	_, ok := b_at.(*AddressType)
	if ok {
		return true
	}
	s_ast, ok := b_at.(*SrcAddressType)
	if ok {
		return at.name == s_ast.GetName()
	}
	s_adt, ok := b_at.(*DstAddressType)
	if ok {
		return at.name == s_adt.GetName()
	}
	
	return false
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

func (a *Address) SetSrcType() {
	a.addr_type = GetSrcAddressType()
}
func (a *Address) SetDstType() {
	a.addr_type = GetDstAddressType()
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

func (a *Address) Match(pk gopacket.Packet) (gopacket.Layer, bool) {
	ipv4_layer := pk.Layer(layers.LayerTypeIPv4)
	if ipv4_layer == nil {
		return nil, false
	}
	ipv4 := ipv4_layer.(*layers.IPv4)
	_, net_cidr, err := net.ParseCIDR(a.GetValue())
	if err != nil {
		return nil, false
	}

	if a.GetType().Compare(GetSrcAddressType()) {
		if net_cidr.Contains(ipv4.SrcIP) != a.IsNegavite() {	// contains address XOR negative (!a.value)
			return ipv4, true
		}
	}
	if a.GetType().Compare(GetDstAddressType()) {
		if net_cidr.Contains(ipv4.DstIP) != a.IsNegavite() {	// contains address XOR negative (!a.value)
			return ipv4, true
		}
	}

	return nil, false
}

func (a *Address) Clone() element.Element {
	el := *a
	return &el
}

func (a *Address) String() string {
	return fmt.Sprintf("{\"%s\": \"%s\"}", a.GetType().GetName(), a.GetValue())
}

// Sets negative value for address (that means we have '! char with this one)
func (a *Address) Negative() {
	a.is_negative = true
}
func (a *Address) IsNegavite() bool {
	return a.is_negative
}

