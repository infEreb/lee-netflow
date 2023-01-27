package validator

import (
	"fmt"
	"lee-netflow/internal/adapters/suricata/rule/constants"
	"lee-netflow/internal/adapters/suricata/rule/element/action"
	"lee-netflow/internal/adapters/suricata/rule/element/direction"
	"lee-netflow/internal/adapters/suricata/rule/element/keyword"
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
	val.SetValid(map[string][]element.Element {
		constants.ActionType.GetName(): {
			action.New("alert"),
			action.New("pass"),
		},
		constants.ProtocolType.GetName(): {
			protocol.New("ip"),
			protocol.New("tcp"),
			protocol.New("udp"),
		},
		// constants.ConstantType.GetName(): {
		// 	constant.New("any", protocol.New("any")),
		// 	constant.New("any", address.New("0.0.0.0/0", constants.AddressType)),
		// 	constant.New("any", portrange.New("0:", [][2]element.Element{{
		// 			port.New(fmt.Sprint(constants.MIN_PORT), constants.PortType),
		// 			port.New(fmt.Sprint(constants.MAX_PORT), constants.PortType),
		// 		},
		// 	}, []element.Element{})),
		// },
		constants.KeywordType.GetName(): {
			keyword.New("any"),
		},
		constants.DirectionType.GetName(): {
			direction.New("->"),
			direction.New("<-"),
			direction.New("<>"),
		},
		constants.OptionType.GetName(): {
			
		},
	})

	return
}

func (sv *SuricataValidator) Validate(elements map[string][]element.Element) error {
	for elem_type, elems := range elements {
		if elem_type == (constants.OptionType.GetName()) {
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
				return fmt.Errorf("%s element %s isnt valid", elem_type, elem.GetValue()) 
			}
		}

	} 
	return nil
}

func (sv *SuricataValidator) GetBaseValidator() *validator.BaseValidator {
	return &sv.BaseValidator
}
