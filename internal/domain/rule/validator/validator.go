package validator

import (
	"fmt"
	"lee-netflow/internal/adapters/suricata/rule/constants"
	"lee-netflow/internal/domain/rule/element"
)

// Interface for rule's elements validation
type Validator interface {
	// Validate all rule elements
	// Returns nil or error with error element information
	Validate(map[element.ElementType][]element.Element) error
	// // Returns nil or error with error element information
	// Available(map[element.ElementType][]element.Element) error
	// // Validate element of element type only
	// IsValid(element.Element) bool
	// IsAvailable(element.Element) bool

	// SetValid(map[element.ElementType][]element.Element)
	// SetAvailable(map[element.ElementType][]element.Element)

	// AddValid(element.Element) error
	// AddAvailable(element.Element) error
	// DelValid(element.Element) error
	// DelAvailable(element.Element) error
}

type BaseValidator struct {
	validElements, availableElements map[element.ElementType][]element.Element
}

func New() (val *BaseValidator) {
	val = &BaseValidator{
		validElements: map[element.ElementType][]element.Element{},
		availableElements: map[element.ElementType][]element.Element{},
	}
	return
}

func (bv *BaseValidator) Validate(elements map[element.ElementType][]element.Element) error {
	for elem_type, elems := range elements {
		if elem_type.Compare(constants.Option) {
			// logic for options compare
		}
		// if we have not this element type in valid just skip validation
		if _, has := bv.validElements[elem_type]; !has {
			continue
		}
		// then validate every element of element type
		for _, elem := range elems {
			// if this element isnt valid element
			if !bv.IsValid(elem) {
				return fmt.Errorf("%s element %s isnt valid", elem_type.GetName(), elem.GetValue()) 
			}
		}

	} 
	return nil
}

func (bv *BaseValidator) Available(elements map[element.ElementType][]element.Element) error {
	for elem_type, elems := range elements {
		// if we have not this element type in valid just skip validation
		if _, has := bv.availableElements[elem_type]; !has {
			continue
		}
		// then validate every element of element type
		for _, elem := range elems {
			// if this element isnt valid element
			if bv.IsAvailable(elem) {
				return fmt.Errorf("%s element %s isnt available", elem_type.GetName(), elem.GetValue()) 
			}
		}

	} 
	return nil
}

func (bv *BaseValidator) IsValid(element element.Element) bool {
	if _, has := bv.validElements[element.GetType()]; !has {
		return false
	}
	// if this element isnt valid element
	valid := func() bool {
		for _, val_elem := range bv.validElements[element.GetType()] {
			if element.Compare(val_elem) {
				return true
			}
		}
		return false
	}()
	if !valid {
		return false 
	}
	return true
}

func (bv *BaseValidator) IsAvailable(element element.Element) bool {
	if _, has := bv.availableElements[element.GetType()]; !has {
		return false
	}
	// if this element isnt valid element
	aval := func() bool {
		for _, aval_elem := range bv.availableElements[element.GetType()] {
			if element.Compare(aval_elem) {
				return true
			}
		}
		return false
	}()
	if !aval {
		return false 
	}
	return true
}

func (bv *BaseValidator) GetValid() map[element.ElementType][]element.Element {
	return bv.validElements
}
func (bv *BaseValidator) SetValid(elements map[element.ElementType][]element.Element) {
	bv.validElements = elements
}

func (bv *BaseValidator) GetAvailable() map[element.ElementType][]element.Element {
	return bv.availableElements
}
func (bv *BaseValidator) SetAvailable(elements map[element.ElementType][]element.Element) {
	bv.availableElements = elements
}

func (bv *BaseValidator) AddValid(element element.Element) error {
	if bv.IsValid(element) {
		return fmt.Errorf("%s element %s already in valid elements", element.GetType().GetName(), element.GetValue())
	}
	bv.validElements[element.GetType()] = append(bv.validElements[element.GetType()], element)
	return nil
}

func (bv *BaseValidator) AddAvailable(element element.Element) error {
	if bv.IsAvailable(element) {
		return fmt.Errorf("%s element %s already in available elements", element.GetType().GetName(), element.GetValue())
	}
	bv.availableElements[element.GetType()] = append(bv.availableElements[element.GetType()], element)
	return nil
}

func (bv *BaseValidator) DelValid(element element.Element) error {
	if !bv.IsValid(element) {
		return fmt.Errorf("%s element %s isnt in valid for deleting", element.GetType().GetName(), element.GetValue())
	}
	// get valid elements slice and find index of our element for deleting
	val_elems := bv.validElements[element.GetType()]
	el_idx := func() int {
		for i, elem := range val_elems {
			if elem.Compare(element) {
				return i
			}
		}
		return -1
	}()
	// change element with last element and remove last element
	val_elems[el_idx] = val_elems[len(val_elems)-1]
	val_elems = val_elems[:len(val_elems)-1]
	// change new value
	bv.validElements[element.GetType()] = val_elems
	return nil
}

func (bv *BaseValidator) DelAvailable(element element.Element) error {
	if !bv.IsAvailable(element) {
		return fmt.Errorf("%s element %s isnt in available for deleting", element.GetType().GetName(), element.GetValue())
	}
	// get valid elements slice and find index of our element for deleting
	aval_elems := bv.availableElements[element.GetType()]
	el_idx := func() int {
		for i, elem := range aval_elems {
			if elem.Compare(element) {
				return i
			}
		}
		return -1
	}()
	// change element with last element and remove last element
	aval_elems[el_idx] = aval_elems[len(aval_elems)-1]
	aval_elems = aval_elems[:len(aval_elems)-1]
	// change new value
	bv.availableElements[element.GetType()] = aval_elems
	return nil
}

