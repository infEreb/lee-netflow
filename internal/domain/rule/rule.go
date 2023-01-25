package rule

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"
	"strconv"
)

// Rule defindes rule struct
type Rule struct {
	name string
	// rule is disabled flag
	// false by default
	disabled bool
	// elements of rule
	elements map[string][]element.Element
}

// Creates new rule with empty elements
// And enabled as default
func New(name string) *Rule {
	return &Rule{
		name: name,
		disabled: false,
		elements: map[string][]element.Element{},
	}
}

// Returns all elements of the parsed rule
func (r *Rule) GetAllElements() map[string][]element.Element {
	return r.elements
}

// Returns elements by element type
func (r *Rule) GetElements(el_type element.ElementType) []element.Element {
	return r.elements[el_type.GetName()]
}

// Adds element to rule by element type
func (r *Rule) AddElement(el element.Element, el_type element.ElementType) error {
	r.elements[el_type.GetName()] = append(r.elements[el_type.GetName()], el)
	return nil
}

// Enable rule
func (r *Rule) Enable() {
	r.disabled = false
}

// Disable rule
func (r *Rule) Disable() {
	r.disabled = true
}

// Returns status of rule
func (r *Rule) IsDisabled() bool {
	return r.disabled
}

func (r *Rule) GetName() string {
	return r.name
}
func (r *Rule) SetName(name string) {
	r.name = name
}

func (r *Rule) String() (s string) {
	s = "{"
	i := 0
	for elem_type, elems := range r.elements {
		s += fmt.Sprintf("\n\t\"%s\": ", elem_type)
		s += "["
		for j, elem := range elems {
			s += fmt.Sprintf("\n\t\t\"%s\"", elem.GetValue())
			if j < len(elems)-1 {
				s += ","
			}
		}
		s += "\n\t]"
		i++
		if i < len(r.elements) {
			s += ","
		}
	}
	s += fmt.Sprintf("\n\t\"Disabled\": \"%s\"", strconv.FormatBool(r.IsDisabled()))
	s += "\n}"
	return
}
