package constant

import (
	"lee-netflow/internal/domain/rule/element"
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
	s_ct, ok := b_ct.(*ConstantType)
	if !ok {
		return false
	}
	return ct.name == s_ct.GetName()
}

// Constant rule element
type Constant struct {
	value      string
	element	element.Element
	isNegative bool
	const_type element.ElementType
}

// Creates new Constant rule element
func New(value string, element element.Element) *Constant {
	return &Constant{
		value:	value,
		element: element,
		isNegative: false,
		const_type: GetConstantType(),
	}
}

// Returns new object of ConstantType type
func GetConstantType() *ConstantType {
	return &ConstantType{
		name: "Constant",
	}
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
// Sets negative value for address (that means we have '! char with this one)
func (c *Constant) Negative() {
	c.isNegative = true
}

func (c *Constant) IsNegavite() bool {
	return c.isNegative
}