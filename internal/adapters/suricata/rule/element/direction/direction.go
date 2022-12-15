package direction

import (
	"lee-netflow/internal/domain/rule/element"
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

func (at *DirectionType) GetName() string {
	return at.name
}

func (at *DirectionType) SetName(dir_type_name string) {
	at.name = dir_type_name
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

