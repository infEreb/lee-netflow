package protocol

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

func (p *Protocol) SetSrcType() {}
func (p *Protocol) SetDstType() {}

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

func (p *Protocol) Match(pk gopacket.Packet) (layer gopacket.Layer, matched bool) {
	switch p.GetValue() {
		case "ip": {
			ipv4_layer := pk.Layer(layers.LayerTypeIPv4)
			if ipv4_layer == nil {
				return nil, false
			}
			layer = ipv4_layer
			break
		}
		case "tcp": {
			tcp_layer := pk.Layer(layers.LayerTypeTCP)
			if tcp_layer == nil {
				return nil, false
			}
			layer = tcp_layer
			break
		}
		case "udp": {
			udp_layer := pk.Layer(layers.LayerTypeUDP)
			if udp_layer == nil {
				return nil, false
			}
			layer = udp_layer
			break
		}
		default: {
			return nil, false
		}
	}
	return layer, true
}

func (p *Protocol) Clone() element.Element {
	el := *p
	return &el
}

func (p *Protocol) String() string {
	return fmt.Sprintf("{\"%s\": \"%s\"}", p.GetType().GetName(), p.GetValue()) 
}
