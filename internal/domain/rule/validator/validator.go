package validator

import "lee-netflow/internal/domain/rule/element"

// Interface for rule's elements validation
type Validator interface {
	// Validate all rule elements
	// Returns nil or error with error element information
	Validate(elements map[element.ElementType][]element.Element) error
	// Validate element of element type only
	IsValid(element.Element) bool
}