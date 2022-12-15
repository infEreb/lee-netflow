package parser

import (
	"lee-netflow/internal/adapters/suricata/rule/element/action"
	"lee-netflow/internal/adapters/suricata/rule/element/address"
	"lee-netflow/internal/adapters/suricata/rule/element/direction"
	"lee-netflow/internal/adapters/suricata/rule/element/option"
	"lee-netflow/internal/adapters/suricata/rule/element/port"
	"lee-netflow/internal/adapters/suricata/rule/element/protocol"
	"lee-netflow/internal/domain/rule/element"
)

// suricata types constants
var (
	Action element.IElementType = action.GetActionType()
	Protocol element.IElementType = protocol.GetProtocolType()
	SrcAddress element.IElementType = address.GetSrcAddressType()
	SrcPort element.IElementType = port.GetSrcPortType()
	Direction element.IElementType = direction.GetDirectionType()
	DstAddress element.IElementType = address.GetDstAddressType()
	DstPort element.IElementType = port.GetDstPortType()
	Option element.IElementType = option.GetOptionType()
)

type SuricataParser struct {
}