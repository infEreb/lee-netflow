package keyword

import (
	"fmt"
	"lee-netflow/internal/domain/rule/element"
	"strings"

	"github.com/google/gopacket"
)

// Keyword type of suricata rules
type KeywordType struct {
	name string
}

// Returns name of KeywordType type
func (ct *KeywordType) GetName() string {
	return ct.name
}

// Sets name of KeywordType type
func (kt *KeywordType) SetName(keyword_type string) {
	kt.name = keyword_type
}

func (kt *KeywordType) Compare(b_kt element.ElementType) bool {
	_, ok := b_kt.(*KeywordType)
	if ok {
		return true
	}
	s_kst, ok := b_kt.(*SrcKeywordType)
	if ok {
		return kt.name == s_kst.GetName()
	}
	s_kdt, ok := b_kt.(*DstKeywordType)
	if ok {
		return kt.name == s_kdt.GetName()
	}
	
	return false
}

type SrcKeywordType struct {
	KeywordType
}
type DstKeywordType struct {
	KeywordType
}

// Keyword rule element
type Keyword struct {
	value      string
	is_negative bool
	keyword_type element.ElementType
}

// Creates new Keyword rule element
func New(value string) *Keyword {
	// if value is negative
	neg := false
	if value[0] == '!' {
		value = strings.TrimPrefix(value, "!")
		neg = true
	}

	return &Keyword{
		value:	value,
		is_negative: neg,
		keyword_type: GetKeywordType(),
	}
}

// Returns new object of KeywordType type
func GetKeywordType() *KeywordType {
	return &KeywordType{
		name: "Keyword",
	}
}
func GetSrcKeywordType() *SrcKeywordType {
	return &SrcKeywordType{
		KeywordType: KeywordType{
			name: "SrcKeywordType",
		},
	}
}
func GetDstKeywordType() *DstKeywordType {
	return &DstKeywordType{
		KeywordType: KeywordType{
			name: "DstKeywordType",
		},
	}
}

func (k *Keyword) SetSrcType() {
	k.keyword_type = GetSrcKeywordType()
}
func (k *Keyword) SetDstType() {
	k.keyword_type = GetDstKeywordType()
}

func (k *Keyword) GetValue() string {
	return k.value
}

func (k *Keyword) SetValue(value string) {
	k.value = value
}

func (k *Keyword) GetType() element.ElementType {
	return k.keyword_type
}

func (k *Keyword) SetType(keyword_type element.ElementType) {
	k.keyword_type = keyword_type
} 

func (k *Keyword) Compare(b_k element.Element) bool {
	s_k, ok := b_k.(*Keyword)
	if !ok {
		return false
	}
	return k.value == s_k.value // && c.element.GetType().Compare(s_c.element.GetType()) && c.element.GetValue() == s_c.element.GetValue()
}

func (k *Keyword) Match(pk gopacket.Packet) (layer gopacket.Layer, matched bool) {
	switch k.GetValue() {
		case "any": {
			return pk.NetworkLayer(), true
		}
		default: {
			return nil, false
		}
	}
}

func (k *Keyword) String() string {
	return fmt.Sprintf("{\"%s\": \"%s\"}", k.GetType().GetName(), k.GetValue())
}

func (k *Keyword) Clone() element.Element {
	el := *k
	return &el
}

// Sets negative value for Keyword (that means we have '! char with this one)
func (k *Keyword) Negative() {
	k.is_negative = true
}

func (k *Keyword) IsNegavite() bool {
	return k.is_negative
}