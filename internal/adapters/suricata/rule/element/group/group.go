package Group

import (
	"lee-netflow/internal/domain/rule/element"
)

// Group type of suricata rules
type GroupType struct {
	name string
}

// Returns name of GroupType type
func (gt *GroupType) GetName() string {
	return gt.name
}

// Sets name of GroupType type
func (gt *GroupType) SetName(group_type_name string) {
	gt.name = group_type_name
}

func (gt *GroupType) Compare(b_gt element.ElementType) bool {
	s_gt, ok := b_gt.(*GroupType)
	if !ok {
		return false
	}
	return gt.name == s_gt.GetName()
}

// Group rule element
type Group struct {
	value      string
	elements	[]element.Element
	is_negative bool
	group_type element.ElementType
}

// Creates new Group rule element of group_type GroupType
func New(value string) *Group {
	return &Group{
		value:	value,
		is_negative: false,
		elements: []element.Element{},
		group_type: GetGroupType(),
	}
}

// Returns new object of GroupType type
func GetGroupType() *GroupType {
	return &GroupType{
		name: "Group",
	}
}

func (g *Group) GetValue() string {
	return g.value
}

func (g *Group) SetValue(value string) {
	g.value = value
}

func (g *Group) GetElements() []element.Element {
	return g.elements
}

func (g *Group) SetElements(elements []element.Element) {
	g.elements = elements
}

func (g *Group) GetType() element.ElementType {
	return g.group_type
}

func (g *Group) SetType(group_type element.ElementType) {
	g.group_type = group_type
} 

func (g *Group) Compare(b_g element.Element) bool {
	s_g, ok := b_g.(*Group)
	if !ok {
		return false
	}
	return g.value == s_g.value
}
// Sets negative value for group (that means we have '! char with this one)
func (g *Group) Negative() {
	g.is_negative = true
}

func (g *Group) IsNegavite() bool {
	return g.is_negative
}
