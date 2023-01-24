package protocol

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"

	"golang.org/x/exp/slices"
)

var (
	validProtocols = []string{
		"ip",
		"icmp",
		"tcp",
		"udp",
		"http",
	}
	availableProtocols = []string{
		"ip",
	}
)

type ProtocolType struct {
	name string
}

func (pt *ProtocolType) GetName() string {
	return pt.name
}

func (pt *ProtocolType) SetName(proto_type_name string) {
	pt.name = proto_type_name
}

func (pt *ProtocolType) Compare(b_pt element.ElementType) bool {
	s_pt, ok := b_pt.(*ProtocolType)
	if !ok {
		return false
	}
	return pt.name == s_pt.GetName()
}

type Protocol struct {
	proto_type element.ElementType
	value      string
}

func New(value string) *Protocol {
	return &Protocol{
		proto_type: GetProtocolType(),
		value: value,
	}
}

func GetProtocolType() *ProtocolType {
	return &ProtocolType{
		name: "Protocol",
	}
}

func (p *Protocol) IsValid() bool {
	return slices.Contains(availableProtocols, p.value)
}
func AddValid(value string, _ []string) error {
	if slices.Contains(validProtocols, value) {
		return fmt.Errorf("Protocol %s already is valid", value)
	}
	validProtocols = append(validProtocols, value)
	return nil
}
func DelValid(value string) error {
	if !slices.Contains(validProtocols, value) {
		return fmt.Errorf("Protocol %s isnt exists as an valid protocol", value)
	}

	del_idx := 0
	for i, v_proto := range validProtocols {
		if v_proto == value {
			del_idx = i
			break
		}
	}

	last_dir := validProtocols[len(validProtocols) - 1]
	validProtocols[del_idx] = last_dir
	validProtocols = validProtocols[:len(validProtocols) - 1]

	return nil
}
func (d *Protocol) IsAvailable() bool {
	return slices.Contains(availableProtocols, d.value)
}
func AddAvailable(value string) error {
	if slices.Contains(availableProtocols, value) {
		return fmt.Errorf("Protocol %s already available", value)
	}
	availableProtocols = append(availableProtocols, value)
	return nil
}
func DelAvailable(value string) error {
	if !slices.Contains(availableProtocols, value) {
		return fmt.Errorf("Protocol %s isnt exists as an available protocol", value)
	}

	del_idx := 0
	for i, a_proto := range availableProtocols {
		if a_proto == value {
			del_idx = i
			break
		}
	}

	last_dir := availableProtocols[len(availableProtocols) - 1]
	availableProtocols[del_idx] = last_dir
	availableProtocols = availableProtocols[:len(availableProtocols) - 1]

	return nil
}
func (p *Protocol) GetValue() string {
	return p.value
}
func (p *Protocol) SetValue(value string) {
	p.value = value
}
func (p *Protocol) GetType() element.ElementType {
	return p.proto_type
}
func (p *Protocol) SetType(proto_type element.ElementType) {
	p.proto_type = proto_type
}

func (p *Protocol) Compare(b_p element.Element) bool {
	s_p, ok := b_p.(*Protocol)
	if !ok {
		return false
	}
	return p.value == s_p.value 
}
