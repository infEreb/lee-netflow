package action

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"

	"github.com/google/gopacket"
)

var (
	validActions = []string{
		"alert",
		"pass",
		"drop",
		"reject",
		"rejectsrc",
		"rejectdst",
		"rejectboth",
	}
	availableActions = []string{
		"alert",
		"pass",
	}
)

// Action type of suricata rule
type ActionType struct {
	name string
}

func (at *ActionType) GetName() string {
	return at.name
}

func (at *ActionType) SetName(act_type_name string) {
	at.name = act_type_name
}

func (at *ActionType) Compare(b_at element.ElementType) bool {
	s_at, ok := b_at.(*ActionType)
	if !ok {
		return false
	}
	return at.name == s_at.GetName()
}

// Action element of suricata rule
type Action struct {
	act_type element.ElementType
	value    string
}

func New(value string) *Action {
	return &Action{
		act_type: GetActionType(),
		value: value,
	}
}

func GetActionType() *ActionType {
	return &ActionType{
		name: "Action",
	} 
}

func (a *Action) GetValue() string {
	return a.value
}

func (a *Action) SetValue(value string) {
	a.value = value
}

func (a *Action) GetType() element.ElementType {
	return a.act_type
}

func (a *Action) SetType(act_type element.ElementType) {
	a.act_type = act_type
}

func (a *Action) Compare(b_a element.Element) bool {
	s_a, ok := b_a.(*Action)
	if !ok {
		return false
	}
	return a.value == s_a.value 
}

func (a *Action) Match(pk gopacket.Packet) (gopacket.Layer, bool) {
	return nil, true
}

func (a *Action) String() string {
	return fmt.Sprintf("\"%s\": \"%s\"", a.GetType().GetName(), a.GetValue())
}