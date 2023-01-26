package constant

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"
	"strings"

	"github.com/google/gopacket"
)

// Constant type of suricata rules
type ConstantType struct {
	name string
}

// Returns name of ConstantType type
func (ct *ConstantType) GetName() string {
	return ct.name
}

// Sets name of ConstantType type
func (ct *ConstantType) SetName(const_type_name string) {
	ct.name = const_type_name
}

func (ct *ConstantType) Compare(b_ct element.ElementType) bool {
	_, ok := b_ct.(*ConstantType)
	if ok {
		return true
	}
	s_cst, ok := b_ct.(*SrcConstantType)
	if ok {
		return ct.name == s_cst.GetName()
	}
	s_cdt, ok := b_ct.(*DstConstantType)
	if ok {
		return ct.name == s_cdt.GetName()
	}
	
	return false
}

type SrcConstantType struct {
	ConstantType
}
type DstConstantType struct {
	ConstantType
}

// Constant rule element
type Constant struct {
	value       string
	element     element.Element
	is_negative bool
	const_type  element.ElementType
}

// Creates new Constant rule element
func New(value string, elem element.Element) *Constant {
	// if value is negative
	neg := false
	if value[0] == '!' {
		value = strings.TrimPrefix(value, "!")
		neg = true
	}

	return &Constant{
		value:       value,
		element:     elem,
		is_negative: neg,
		const_type:  GetConstantType(),
	}
}

// Returns new object of ConstantType type
func GetConstantType() *ConstantType {
	return &ConstantType{
		name: "Constant",
	}
}
func GetSrcConstantType() *SrcConstantType {
	return &SrcConstantType{
		ConstantType: ConstantType{
			name: "SrcConstantType",
		},
	}
}
func GetDstConstantType() *DstConstantType {
	return &DstConstantType{
		ConstantType: ConstantType{
			name: "DstConstantType",
		},
	}
}

func (c *Constant) SetSrcType() {
	c.const_type = GetSrcConstantType()
	c.element.SetSrcType()
}
func (c *Constant) SetDstType() {
	c.const_type = GetDstConstantType()
	c.element.SetDstType()
}

func (c *Constant) GetValue() string {
	return c.value
}

func (c *Constant) SetValue(value string) {
	c.value = value
}

func (c *Constant) GetElement() element.Element {
	return c.element
}

func (c *Constant) SetElement(element element.Element) {
	c.element = element
}

func (c *Constant) GetType() element.ElementType {
	return c.const_type
}

func (c *Constant) SetType(const_type element.ElementType) {
	c.const_type = const_type
}

func (c *Constant) Compare(b_c element.Element) bool {
	s_c, ok := b_c.(*Constant)
	if !ok {
		return false
	}
	return c.value == s_c.value // && c.element.GetType().Compare(s_c.element.GetType()) && c.element.GetValue() == s_c.element.GetValue()
}

func (c *Constant) Match(pk gopacket.Packet) (layer gopacket.Layer, matched bool) {
	layer, matched = c.element.Match(pk)
	if matched != c.IsNegavite() { // XOR
		return layer, true
	}

	return nil, false
}

func (c *Constant) Clone() element.Element {
	el := *c
	el.SetElement(c.element.Clone())
	return &el
}

func (c *Constant) String() string {
	return fmt.Sprintf("{\"%s\": %s}", c.GetValue(), c.GetElement().String())
}

// Sets negative value for Constant (that means we have '! char with this one)
func (c *Constant) Negative() {
	c.is_negative = true
}

func (c *Constant) IsNegavite() bool {
	return c.is_negative
}
