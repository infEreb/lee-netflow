package option

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"
	"strings"

	"golang.org/x/exp/slices"
)

var (
	validOptions = []string{
		"msg",
		"contains",
	}
	availableOptions = []string{
		"msg",
	}
)

type OptionType struct {
	name string
}

func (ot *OptionType) GetName() string {
	return ot.name
}

func (ot *OptionType) SetName(opt_type_name string) {
	ot.name = opt_type_name
}

func (ot *OptionType) Compare(b_ot element.ElementType) bool {
	s_ot, ok := b_ot.(*OptionType)
	if !ok {
		return false
	}
	return ot.name == s_ot.GetName()
}

type Option struct {
	opt_type element.ElementType
	value    string
}

func New(value string) *Option {
	return &Option{
		opt_type: GetOptionType(),
		value:    value,
	}
}

func GetOptionType() *OptionType {
	return &OptionType{
		name: "Option",
	}
}

func (o *Option) IsValid() bool {
	// key:value (msg:"some")
	if strings.Contains(o.value, ":") {
		opt := strings.Split(o.value, ":")
		if len(opt) != 2 {
			return false
		}
		key, _:= opt[0], opt[1]
		return slices.Contains(validOptions, key)
	}
	// key (msg)
	return slices.Contains(validOptions, o.value)
	
}
func AddValid(value string, _ []string) error {
	if slices.Contains(validOptions, value) {
		return fmt.Errorf("Option %s already is valid", value)
	}
	validOptions = append(validOptions, value)
	return nil
}
func DelValid(value string) error {
	if !slices.Contains(validOptions, value) {
		return fmt.Errorf("Option %s isnt exists as an valid option", value)
	}

	del_idx := 0
	for i, v_opt := range validOptions {
		if v_opt == value {
			del_idx = i
			break
		}
	}

	last_dir := validOptions[len(validOptions) - 1]
	validOptions[del_idx] = last_dir
	validOptions = validOptions[:len(validOptions) - 1]

	return nil
}
func (o *Option) IsAvailable() bool {
	if strings.Contains(o.value, ":") {
		opt := strings.Split(o.value, ":")
		if len(opt) != 2 {
			return false
		}
		key, _:= opt[0], opt[1]
		return slices.Contains(availableOptions, key)
	}
	return slices.Contains(availableOptions, o.value)
}
func AddAvailable(value string) error {
	if slices.Contains(availableOptions, value) {
		return fmt.Errorf("Option %s already available", value)
	}
	availableOptions = append(availableOptions, value)
	return nil
}
func DelAvailable(value string) error {
	if !slices.Contains(availableOptions, value) {
		return fmt.Errorf("Option %s isnt exists as an available option", value)
	}

	del_idx := 0
	for i, a_opt := range availableOptions {
		if a_opt == value {
			del_idx = i
			break
		}
	}

	last_dir := availableOptions[len(availableOptions) - 1]
	availableOptions[del_idx] = last_dir
	availableOptions = availableOptions[:len(availableOptions) - 1]

	return nil
}

func (o *Option) GetValue() string {
	return o.value
}
func (o *Option) SetValue(value string) {
	o.value = value
}
func (o *Option) GetType() element.ElementType {
	return o.opt_type
}
func (o *Option) SetType(opt_type element.ElementType) {
	o.opt_type = opt_type
}

func (o *Option) Compare(b_o element.Element) bool {
	s_o, ok := b_o.(*Option)
	if !ok {
		return false
	}
	return o.value == s_o.value 
}


