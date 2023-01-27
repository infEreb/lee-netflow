package group

import (
	"lee-netflow/internal/domain/rule/element"
	"strings"

	"github.com/google/gopacket"
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
	_, ok := b_gt.(*GroupType)
	if ok {
		return true
	}
	s_gst, ok := b_gt.(*SrcGroupType)
	if ok {
		return gt.name == s_gst.GetName()
	}
	s_gdt, ok := b_gt.(*DstGroupType)
	if ok {
		return gt.name == s_gdt.GetName()
	}
	
	return false
}

type SrcGroupType struct {
	GroupType
}
type DstGroupType struct {
	GroupType
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
	// if value is negative
	neg := false
	if value[0] == '!' {
		value = strings.TrimPrefix(value, "!")
		neg = true
	}

	return &Group{
		value:	value,
		is_negative: neg,
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
func GetSrcGroupType() *SrcGroupType {
	return &SrcGroupType{
		GroupType: GroupType{
			name: "SrcGroupType",
		},
	}
}
func GetDstGroupType() *DstGroupType {
	return &DstGroupType{
		GroupType: GroupType{
			name: "DstGroupType",
		},
	}
}

func (g *Group) SetSrcType() {
	g.group_type = GetSrcGroupType()
	for _, el := range g.elements {
		el.SetSrcType()
	}
}
func (g *Group) SetDstType() {
	g.group_type = GetDstGroupType()
	for _, el := range g.elements {
		el.SetDstType()
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
func (g *Group) AddElement(element element.Element) {
	g.elements = append(g.elements, element)
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
// Returns last matched layer if matched group
func (g *Group) Match(pk gopacket.Packet) (layer gopacket.Layer, matched  bool) {
	for _, el := range g.GetElements() {
		layer, matched = el.Match(pk)
		if matched != g.IsNegavite() {		// matched XOR g.is_negative
			return layer, true
		}
	}

	return layer, false
}

func (g *Group) String() string {
	s := "{"
	for i, l := 0, len(g.GetElements()); i < l; i++ {
		s += g.GetElements()[i].String()
		if i < l-1 {
			s += ", "
		}
	}
	s += "}"
	return s
}

func (g *Group) Clone() element.Element {
	el := *g
	cp_g_els := []element.Element{}
	for _, gel := range g.elements {
		cp_g_els = append(cp_g_els, gel.Clone())
	}
	el.SetElements(cp_g_els)
	return &el
}

// Sets negative value for group (that means we have '! char with this one)
func (g *Group) Negative() {
	g.is_negative = true
}

func (g *Group) IsNegavite() bool {
	return g.is_negative
}
