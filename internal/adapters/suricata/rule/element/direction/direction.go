package direction

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"

	"github.com/google/gopacket"
)

var (
	validDirections = []string{
		"->",
		"<-",
		"<>",
	}
	availableDirections = []string{
		"->",
	}
)

// Direction type of suricata rules
type DirectionType struct {
	name string
}

func (dt *DirectionType) GetName() string {
	return dt.name
}

func (dt *DirectionType) SetName(dir_type_name string) {
	dt.name = dir_type_name
}

func (dt *DirectionType) Compare(b_dt element.ElementType) bool {
	s_dt, ok := b_dt.(*DirectionType)
	if !ok {
		return false
	}
	return dt.name == s_dt.GetName()
}

// Direction rule element
type Direction struct {
	dir_type element.ElementType
	value    string
}

func New(value string) *Direction {
	return &Direction{
		dir_type: GetDirectionType(),
		value:    value,
	}
}

// Returns new object of DirectionType type
func GetDirectionType() *DirectionType {
	return &DirectionType{
		name: "Direction",
	}
}

func (d *Direction) GetValue() string {
	return d.value
}

func (d *Direction) SetValue(value string) {
	d.value = value
} 

func (d *Direction) GetType() element.ElementType {
	return d.dir_type
}

func (d *Direction) SetType(dir_type element.ElementType) {
	d.dir_type = dir_type
}

func (d *Direction) Compare(b_d element.Element) bool {
	s_d, ok := b_d.(*Direction)
	if !ok {
		return false
	}
	return d.value == s_d.value 
}

func (d *Direction) Match(pk gopacket.Packet) (gopacket.Layer, bool) {
	return nil, true
}

func (d *Direction) String() string {
	return fmt.Sprintf("\"%s\": \"%s\"", d.GetType().GetName(), d.GetValue())
}
