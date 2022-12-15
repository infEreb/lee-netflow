package protocol

import "lee-netflow/internal/domain/rule/element"

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

type Protocol struct {
	proto_type element.IElementType
	value      string
}
