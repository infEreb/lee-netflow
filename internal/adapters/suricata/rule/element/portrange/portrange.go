package portrange

import (
	"lee-netflow/internal/domain/rule/element"
	"strings"
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
	s_rpt, ok := b_rpt.(*PortRangeType)
	if !ok {
		return false
	}
	return rpt.name == s_rpt.GetName()
}

// PortRange rule element
type PortRange struct {
	value      string
	ranges     [][2]element.Element
	ports 		[]element.Element
	is_negative bool
	portrange_type element.ElementType
}

// Creates new PortRange rule element of PortRange_type PortRangeType
func New(value string, ranges [][2]element.Element, ports []element.Element) *PortRange {
	// if value is negative
	neg := false
	if value[0] == '!' {
		value = strings.TrimPrefix(value, "!")
		neg = true
	}

	return &PortRange{
		value:	value,
		ranges: ranges,
		ports: ports,
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

func (pr *PortRange) GetValue() string {
	return pr.value
}
func (pr *PortRange) SetValue(value string) {
	pr.value = value
}

func (pr *PortRange) GetRanges() [][2]element.Element {
	return pr.ranges
}
func (pr *PortRange) SetRanges(ranges [][2]element.Element) {
	pr.ranges = ranges
}
func (pr *PortRange) AddRange(rang [2]element.Element) {
	pr.ranges = append(pr.ranges, rang)
}

func (pr *PortRange) GetPorts() []element.Element {
	return pr.ports
}
func (pr *PortRange) SetPorts(ports []element.Element) {
	pr.ports = ports
}
func (pr *PortRange) AddPort(port element.Element) {
	pr.ports = append(pr.ports, port)
}



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
// Sets negative value for PortRange (that means we have '! char with this one)
func (pr *PortRange) Negative() {
	pr.is_negative = true
}

func (pr *PortRange) IsNegavite() bool {
	return pr.is_negative
}