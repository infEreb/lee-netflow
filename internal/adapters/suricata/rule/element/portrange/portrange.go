package portrange

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"
	"strconv"
	"strings"

	"github.com/google/gopacket"
)

// PortRange type of suricata rules
type PortRangeType struct {
	name string
}

// Returns name of PortRangeType type
func (rpt *PortRangeType) GetName() string {
	return rpt.name
}

// Sets name of PortRangeType type
func (rpt *PortRangeType) SetName(portrange_type_name string) {
	rpt.name = portrange_type_name
}

func (rpt *PortRangeType) Compare(b_rpt element.ElementType) bool {
	_, ok := b_rpt.(*PortRangeType)
	if ok {
		return true
	}
	s_rpst, ok := b_rpt.(*SrcPortRangeType)
	if ok {
		return rpt.name == s_rpst.GetName()
	}
	s_rpdt, ok := b_rpt.(*DstPortRangeType)
	if ok {
		return rpt.name == s_rpdt.GetName()
	}
	
	return false
}

type SrcPortRangeType struct {
	PortRangeType
}
type DstPortRangeType struct {
	PortRangeType
}

// PortRange rule element
type PortRange struct {
	value      string
	ranges     [2]element.Element
	is_negative bool
	portrange_type element.ElementType
}

// Creates new PortRange rule element of PortRange_type PortRangeType
func New(value string, ranges [2]element.Element) *PortRange {
	// if value is negative
	neg := false
	if value[0] == '!' {
		value = strings.TrimPrefix(value, "!")
		neg = true
	}

	return &PortRange{
		value:	value,
		ranges: ranges,
		is_negative: neg,
		portrange_type: GetPortRangeType(),
	}
}

// Returns new object of PortRangeType type
func GetPortRangeType() *PortRangeType {
	return &PortRangeType{
		name: "PortRange",
	}
}
func GetSrcPortRangeType() *SrcPortRangeType {
	return &SrcPortRangeType{
		PortRangeType: PortRangeType{
			name: "SrcPortRangeType",
		},
	}
}
func GetDstPortRangeType() *DstPortRangeType {
	return &DstPortRangeType{
		PortRangeType: PortRangeType{
			name: "DstPortRangeType",
		},
	}
}

func (pr *PortRange) SetSrcType() {
	pr.portrange_type = GetSrcPortRangeType()
	for _, el := range pr.ranges {
		el.SetSrcType()
	}
}
func (pr *PortRange) SetDstType() {
	pr.portrange_type = GetDstPortRangeType()
	for _, el := range pr.ranges {
		el.SetDstType()
	}
}

func (pr *PortRange) GetValue() string {
	return pr.value
}
func (pr *PortRange) SetValue(value string) {
	pr.value = value
}

func (pr *PortRange) GetRanges() [2]element.Element {
	return pr.ranges
}
func (pr *PortRange) SetRanges(ranges [2]element.Element) {
	pr.ranges = ranges
}
func (pr *PortRange) SetRange(rang [2]element.Element) {
	pr.ranges = rang
}

// func (pr *PortRange) GetPorts() []element.Element {
// 	return pr.ports
// }
// func (pr *PortRange) SetPorts(ports []element.Element) {
// 	pr.ports = ports
// }
// func (pr *PortRange) AddPort(port element.Element) {
// 	pr.ports = append(pr.ports, port)
// }



func (pr *PortRange) GetType() element.ElementType {
	return pr.portrange_type
}

func (pr *PortRange) SetType(portrange_type element.ElementType) {
	pr.portrange_type = portrange_type
} 

func (pr *PortRange) Compare(b_pr element.Element) bool {
	s_pr, ok := b_pr.(*PortRange)
	if !ok {
		return false
	}
	return pr.value == s_pr.value
}

func (pr *PortRange) Match(pk gopacket.Packet) (layer gopacket.Layer, matched bool) {
	trans_layer := pk.TransportLayer()
	if trans_layer != nil {
		return nil, false
	}

	port := ""

	if pr.GetType().Compare(GetSrcPortRangeType()) {
		port = trans_layer.TransportFlow().Src().String()
	}
	if pr.GetType().Compare(GetDstPortRangeType()) {
		port = trans_layer.TransportFlow().Dst().String()
	}
	if port == "" {
		return nil, false
	}

	num_port, _ := strconv.Atoi(port)
	num_min, _ := strconv.Atoi(pr.GetRanges()[0].GetValue())
	num_max, _ := strconv.Atoi(pr.GetRanges()[1].GetValue())
	if num_port >= num_min && num_port <= num_max {
		return trans_layer, true
	}

	// p_t := pr.GetPorts()
	// pr_t := pr.GetRanges()

	// // check ports in port range
	// for _, p_i := range p_t {
	// 	layer, matched = p_i.Match(pk)
	// 	if !(!matched != pr.IsNegavite()) {		// XAND
	// 		return nil, false
	// 	}
	// }
	// // check port ranges
	// for _, pr_i := range pr_t {
	// 	for _, pr_i_port := range pr_i {
	// 		layer, matched = pr_i_port.Match(pk)
	// 		if !(!matched != pr.IsNegavite()) {		// XAND
	// 			return nil, false
	// 		}
	// 	}
	// }

	return nil, false
}

func (pr *PortRange) Clone() element.Element {
	el := *pr
	pr_els := [2]element.Element{}
	for i, pr_el := range pr.ranges {
		pr_els[i] = pr_el
	}
	el.SetRange(pr_els)
	return &el
}

func (pr *PortRange) String() string {
	// s := "{"
	// s += fmt.Sprintf("\"%s\": {", "Ports")
	// for i, l := 0, len(pr.GetPorts()); i < l; i++ {
	// 	s += pr.GetPorts()[i].String()
	// 	if i < l-1 {
	// 		s += ", "
	// 	}
	// }
	// s += "}"

	// s += fmt.Sprintf(", \"%s\": {", GetPortRangeType().GetName())
	// for i, l := 0, len(pr.GetRanges()); i < l; i++ {
	// 	s += fmt.Sprintf("{%s, %s}", pr.GetRanges()[i][0].String(), pr.GetRanges()[i][1].String())
	// 	if i < l-1 {
	// 		s += ", "
	// 	}
	// }
	// s += "}"
	// s += "}"
	return fmt.Sprintf("{\"%s\": \"%s\"}", pr.GetType().GetName(), pr.GetValue())
}

// Sets negative value for PortRange (that means we have '! char with this one)
func (pr *PortRange) Negative() {
	pr.is_negative = true
}

func (pr *PortRange) IsNegavite() bool {
	return pr.is_negative
}