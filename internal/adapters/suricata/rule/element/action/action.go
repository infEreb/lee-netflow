package action

import (
	"lee-netflow/internal/domain/rule/element"
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

