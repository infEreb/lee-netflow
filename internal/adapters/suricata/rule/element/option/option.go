package option

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"

	"github.com/google/gopacket"
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

func (o *Option) Match(pk gopacket.Packet) (gopacket.Layer, bool) {
	return nil, true
}

func (o *Option) String() string {
	return fmt.Sprintf("\"%s\": \"%s\"", o.GetType().GetName(), o.GetValue())
}

