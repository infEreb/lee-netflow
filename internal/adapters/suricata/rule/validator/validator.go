package validator

import (
	"fmt"
	"lee-netflow/internal/adapters/suricata/rule/constants"
	"lee-netflow/internal/adapters/suricata/rule/element/action"
	"lee-netflow/internal/adapters/suricata/rule/element/address"
	"lee-netflow/internal/adapters/suricata/rule/element/constant"
	"lee-netflow/internal/adapters/suricata/rule/element/direction"
	"lee-netflow/internal/adapters/suricata/rule/element/port"
	"lee-netflow/internal/adapters/suricata/rule/element/protocol"
	"lee-netflow/internal/domain/rule/element"
	"lee-netflow/internal/domain/rule/validator"
)

type SuricataValidator struct {
	validator.BaseValidator
}

func New() (val *SuricataValidator) {
	val = &SuricataValidator{
		BaseValidator: *validator.New(),
	}
	// set valid elements for validator
	val.SetValid(map[element.ElementType][]element.Element {
		constants.Action: {
			action.New("alert"),
			action.New("pass"),
		},
		constants.Protocol: {
			protocol.New("ip"),
			protocol.New("tcp"),
			protocol.New("http"),
		},
		constants.Constant: {
			constant.New("any", address.New("any", constants.SrcAddress)),
			constant.New("any", address.New("any", constants.DstAddress)),
			constant.New("any", port.New("any", constants.SrcPort)),
			constant.New("any", port.New("any", constants.DstPort)),
		},
		constants.Direction: {
			direction.New("->"),
			direction.New("<-"),
			direction.New("<>"),
		},
		constants.Option: {

		},
	})

	return
}

func (sv *SuricataValidator) Validate(elements map[element.ElementType][]element.Element) error {
	for elem_type, elems := range elements {
		if elem_type.Compare(constants.Option) {
			// logic for options compare
		}
		// if we have not this element type in valid just skip validation
		if _, has := sv.BaseValidator.GetValid()[elem_type]; !has {
			continue
		}
		// then validate every element of element type
		for _, elem := range elems {
			// if this element isnt valid element
			if !sv.IsValid(elem) {
				return fmt.Errorf("%s element %s isnt valid", elem_type.GetName(), elem.GetValue()) 
			}
		}

	} 
	return nil
}
