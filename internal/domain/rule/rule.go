package rule

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"
)

// Rule defindes rule struct
type Rule struct {
	// rule is disabled flag
	// false by default
	disabled bool
	// elements of rule
	elements map[string][]element.Element
}

// Creates new rule with empty elements
// And enabled as default
func New() *Rule {
	return &Rule{
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

func (r *Rule) String() (s string) {
	s = "{"
	for elem_type, elems := range r.elements {
		s += fmt.Sprintf("\n\t\"%s\": ", elem_type)
		s += "["
		for i, elem := range elems {
			s += fmt.Sprintf("\n\t\t\"%s\"", elem.GetValue())
			if i < len(elems) - 1 {
				s += ","
			}
		}
		s += "\n\t]"
	}
	s += "\n}"
	return
}