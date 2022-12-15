package matcher

import (
	"fmt"
	"lee-netflow/internal/domain/rule"

	"github.com/google/gopacket"
)

func New() *SuricataMatcher {
	return &SuricataMatcher{}
}

func (sm *SuricataMatcher) Match(packet gopacket.Packet, rule *rule.Rule) (_ bool, err error) {
	pack_proto_l3 := packet.NetworkLayer().LayerType().String()
	pack_proto_l4 := packet.TransportLayer().LayerType().String()

	fmt.Println(pack_proto_l3, pack_proto_l4)

	return true, nil
}