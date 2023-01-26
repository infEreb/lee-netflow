package element

import "github.com/google/gopacket"

// Interface for element type for rule elements
type ElementType interface {
	GetName() string
	SetName(string)
	Compare(ElementType) bool
}

// Elements interface for rule elements
type Element interface {
	// Returns element value as string 
	GetValue() string
	SetValue(string)
	// Returns element type
	GetType() ElementType
	SetType(ElementType)
	// Returns true if two elements and elements types are equal 
	Compare(Element) bool
	// Matches packet with this element
	// Returns layer with data that has been matched and result of match 
	Match(gopacket.Packet) (gopacket.Layer, bool)

	SetSrcType()
	SetDstType()

	Clone() Element

	String() string
}
