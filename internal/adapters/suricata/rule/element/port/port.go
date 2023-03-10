package port

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"
	"strings"

	"github.com/google/gopacket"
	"golang.org/x/exp/slices"
)

var (
	validPortConstants = map[string][]string{
		"any": {
			"[:]",
		},
	}
	availablePortConstants = []string{
		"any",
	}
)

type PortType struct {
	name string
}

func (pt *PortType) GetName() string {
	return pt.name
}

func (pt *PortType) SetName(port_type_name string) {
	pt.name = port_type_name
}

func (pt *PortType) Compare(b_pt element.ElementType) bool {
	_, ok := b_pt.(*PortType)
	if ok {
		return true
	}
	s_pst, ok := b_pt.(*SrcPortType)
	if ok {
		return pt.name == s_pst.GetName()
	}
	s_pdt, ok := b_pt.(*DstPortType)
	if ok {
		return pt.name == s_pdt.GetName()
	}
	
	return false
}

type SrcPortType struct {
	PortType
}

type DstPortType struct {
	PortType
}

type Port struct {
	value       string
	is_negative bool
	port_type   element.ElementType
}

func New(value string, port_type element.ElementType) *Port {
	// if value is negative
	neg := false
	if value[0] == '!' {
		value = strings.TrimPrefix(value, "!")
		neg = true
	}

	return &Port{
		value:       value,
		is_negative: neg,
		port_type:   port_type,
	}
}

func GetPortType() *PortType {
	return &PortType{
		name: "Port",
	}
}
func GetSrcPortType() *SrcPortType {
	return &SrcPortType{
		PortType: PortType{
			name: "SrcPort",
		},
	}
}
func GetDstPortType() *DstPortType {
	return &DstPortType{
		PortType: PortType{
			name: "DstPort",
		},
	}
}

func (p *Port) SetSrcType() {
	p.port_type = GetSrcPortType()
}
func (p *Port) SetDstType() {
	p.port_type = GetDstPortType()
}

func DelValid(const_name string) error {
	if _, has := validPortConstants[const_name]; !has {
		return fmt.Errorf("Constant %s isnt exists", const_name)
	}
	delete(validPortConstants, const_name)
	return nil
}
func AddAvailable(value string) error {
	if slices.Contains(availablePortConstants, value) {
		return fmt.Errorf("Port %s already available.", value)
	}
	availablePortConstants = append(availablePortConstants, value)
	return nil
}
func DelAvailable(value string) error {
	if !slices.Contains(availablePortConstants, value) {
		return fmt.Errorf("Port %s isnt exists as an available port.", value)
	}

	del_idx := 0
	for i, a_port := range availablePortConstants {
		if a_port == value {
			del_idx = i
			break
		}
	}

	last_act := availablePortConstants[len(availablePortConstants)-1]
	availablePortConstants[del_idx] = last_act
	availablePortConstants = availablePortConstants[:len(availablePortConstants)-1]

	return nil
}
func (p *Port) GetValue() string {
	return p.value
}
func (p *Port) SetValue(value string) {
	p.value = value
}
func (p *Port) GetType() element.ElementType {
	return p.port_type
}
func (p *Port) SetType(port_type element.ElementType) {
	p.port_type = port_type
}

func (p *Port) Compare(b_p element.Element) bool {
	s_p, ok := b_p.(*Port)
	if !ok {
		return false
	}
	return p.value == s_p.value
}

func (p *Port) Match(pk gopacket.Packet) (gopacket.Layer, bool) {
	trans_layer := pk.TransportLayer()
	if trans_layer != nil {
		return nil, false
	}

	src := trans_layer.TransportFlow().Src().String()
	dst := trans_layer.TransportFlow().Dst().String()
	if p.GetType().Compare(GetSrcPortType()) {
		if (p.GetValue() == src) != p.IsNegavite() {	// contains Port XOR negative (!a.value)
			return trans_layer, true
		}
	}
	if p.GetType().Compare(GetDstPortType()) {
		if (p.GetValue() == dst) != p.IsNegavite() {	// contains Port XOR negative (!a.value)
			return trans_layer, true
		}
	}

	return nil, false
}

func (p *Port) Clone() element.Element {
	el := *p
	return &el
}

func (p *Port) String() string {
	return fmt.Sprintf("{\"%s\": \"%s\"}", p.GetType().GetName(), p.GetValue())
}

func (p *Port) Negative() {
	p.is_negative = true
}
func (p *Port) IsNegavite() bool {
	return p.is_negative
}

// func CheckValidElem(port_elem string) bool {
// 	if IsConstant(port_elem) {
// 		return true
// 	}
// 	if IsPort(port_elem) {
// 		return true
// 	}
// 	if IsGroup(port_elem) {
// 		group_str := strings.TrimPrefix(port_elem, "!")
// 		group_str = strings.TrimPrefix(group_str, "[")
// 		group_str = strings.TrimSuffix(group_str, "]")
// 		group_elems := strings.Split(strings.Replace(group_str, " ", "", -1), ",")
// 		for _, elem := range group_elems {
// 			if !CheckValidElem(elem) {
// 				return false
// 			}
// 		}
// 		return true
// 	}
// 	if IsRange(port_elem) {
// 		port_elems := strings.Split(strings.Trim(port_elem, "[]"), ":")
// 		if len(port_elems) != 2 {
// 			return false
// 		}
// 		if !IsPort(port_elems[0]) || !IsPort(port_elems[1]) {
// 			return false
// 		}

// 	}

// 	return false
// }

// func CheckAvailableElem(port_elem string) bool {
// 	if IsConstant(port_elem) {
// 		const_str := strings.TrimPrefix(port_elem, "!")
// 		if slices.Contains(availablePortConstants, const_str) {
// 			return true
// 		}
// 		return false
// 	}
// 	if IsPort(port_elem) {
// 		return true
// 	}
// 	if IsGroup(port_elem) {
// 		group_str := strings.Trim(port_elem, "[]")
// 		group_elems := strings.Split(strings.Replace(group_str, " ", "", -1), ",")
// 		for _, elem := range group_elems {
// 			if !CheckAvailableElem(elem) {
// 				return false
// 			}
// 		}
// 		return true
// 	}
// 	// cannot be other type
// 	return true
// }
