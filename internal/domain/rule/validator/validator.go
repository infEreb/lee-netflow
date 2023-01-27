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
	Validate(map[string][]element.Element) error
	GetBaseValidator() *BaseValidator
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
	validElements, availableElements map[string][]element.Element
}

func New() (val *BaseValidator) {
	val = &BaseValidator{
		validElements: map[string][]element.Element{},
		availableElements: map[string][]element.Element{},
	}
	return
}

func (bv *BaseValidator) Validate(elements map[string][]element.Element) error {
	for elem_type, elems := range elements {
		if elem_type == (constants.OptionType.GetName()) {
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
				return fmt.Errorf("%s element %s isnt valid", elem_type, elem.GetValue()) 
			}
		}

	} 
	return nil
}

func (bv *BaseValidator) Available(elements map[string][]element.Element) error {
	for elem_type, elems := range elements {
		// if we have not this element type in valid just skip validation
		if _, has := bv.availableElements[elem_type]; !has {
			continue
		}
		// then validate every element of element type
		for _, elem := range elems {
			// if this element isnt valid element
			if bv.IsAvailable(elem) {
				return fmt.Errorf("%s element %s isnt available", elem_type, elem.GetValue()) 
			}
		}

	} 
	return nil
}

func (bv *BaseValidator) IsValid(element element.Element) bool {
	if _, has := bv.validElements[element.GetType().GetName()]; !has {
		return false
	}
	// if this element isnt valid element
	valid := func() bool {
		for _, val_elem := range bv.validElements[element.GetType().GetName()] {
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
	if _, has := bv.availableElements[element.GetType().GetName()]; !has {
		return false
	}
	// if this element isnt valid element
	aval := func() bool {
		for _, aval_elem := range bv.availableElements[element.GetType().GetName()] {
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

func (bv *BaseValidator) GetValid() map[string][]element.Element {
	return bv.validElements
}
func (bv *BaseValidator) SetValid(elements map[string][]element.Element) {
	bv.validElements = elements
}
func (bv *BaseValidator) GetValidByElement(elem element.Element) (element.Element, error) {
	for _, el := range bv.validElements[elem.GetType().GetName()] {
		if el.Compare(elem) {
			return el, nil
		}
	}
	// return yourself and error
	return elem, fmt.Errorf("Has not valid element")
}
func (bv *BaseValidator) GetValidByType(el_type element.ElementType) ([]element.Element, error) {
	elems, has := bv.validElements[el_type.GetName()]
	if !has {
		return nil, fmt.Errorf("Has not valid elements with %s type", el_type.GetName())
	}

	return elems, nil
}

func (bv *BaseValidator) GetAvailable() map[string][]element.Element {
	return bv.availableElements
}
func (bv *BaseValidator) SetAvailable(elements map[string][]element.Element) {
	bv.availableElements = elements
}
func (bv *BaseValidator) GetAvailableByElement(elem element.Element) (element.Element, error) {
	for _, el := range bv.availableElements[elem.GetType().GetName()] {
		if el.Compare(elem) {
			return el, nil
		}
	}
	// return yourself and error
	return elem, fmt.Errorf("Has not available element")
}
func (bv *BaseValidator) GetAvailableByType(el_type element.ElementType) ([]element.Element, error) {
	elems, has := bv.availableElements[el_type.GetName()]
	if !has {
		return nil, fmt.Errorf("Has not available elements with %s type", el_type.GetName())
	}

	return elems, nil
}

func (bv *BaseValidator) AddValid(element element.Element) error {
	if bv.IsValid(element) {
		return fmt.Errorf("%s element %s already in valid elements", element.GetType().GetName(), element.GetValue())
	}
	bv.validElements[element.GetType().GetName()] = append(bv.validElements[element.GetType().GetName()], element)
	return nil
}

func (bv *BaseValidator) AddAvailable(element element.Element) error {
	if bv.IsAvailable(element) {
		return fmt.Errorf("%s element %s already in available elements", element.GetType().GetName(), element.GetValue())
	}
	bv.availableElements[element.GetType().GetName()] = append(bv.availableElements[element.GetType().GetName()], element)
	return nil
}

func (bv *BaseValidator) DelValid(element element.Element) error {
	if !bv.IsValid(element) {
		return fmt.Errorf("%s element %s isnt in valid for deleting", element.GetType().GetName(), element.GetValue())
	}
	// get valid elements slice and find index of our element for deleting
	val_elems := bv.validElements[element.GetType().GetName()]
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
	bv.validElements[element.GetType().GetName()] = val_elems
	return nil
}

func (bv *BaseValidator) DelAvailable(element element.Element) error {
	if !bv.IsAvailable(element) {
		return fmt.Errorf("%s element %s isnt in available for deleting", element.GetType().GetName(), element.GetValue())
	}
	// get valid elements slice and find index of our element for deleting
	aval_elems := bv.availableElements[element.GetType().GetName()]
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
	bv.availableElements[element.GetType().GetName()] = aval_elems
	return nil
}

