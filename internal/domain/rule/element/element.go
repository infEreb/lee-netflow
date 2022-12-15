package element

// Interface for element type for rule elements
type ElementType interface {
	GetName() string
	SetName(string)
}

// Elements interface for rule elements
type Element interface {
	// Returns element value as string 
	GetValue() string
	SetValue(string)
	// Returns element type
	GetType() ElementType
	SetType(ElementType)
}
