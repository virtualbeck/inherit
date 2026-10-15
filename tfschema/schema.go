// Package tfschema exposes the bundled AWS provider schema.
package tfschema

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

//go:embed schema/aws.min.json.gz
var embedded []byte

type Kind uint8

const (
	KindString Kind = iota
	KindNumber
	KindBool
	KindList
	KindSet
	KindMap
	KindObject
	KindTuple
	KindDynamic
)

type Type struct {
	Kind  Kind
	Elem  *Type
	Attrs map[string]*Type
}

// IsCollectionOfObject: a list/set of objects, a repeatable block.
func (t *Type) IsCollectionOfObject() bool {
	return t != nil && (t.Kind == KindList || t.Kind == KindSet) && t.Elem != nil && t.Elem.Kind == KindObject
}

type Attribute struct {
	Type       *Type
	Required   bool
	Optional   bool
	Computed   bool
	NestedMode string
	Nested     *Block
}

// Settable reports whether config may set the attribute.
func (a *Attribute) Settable() bool { return a != nil && (a.Optional || a.Required) }

func (a *Attribute) IsMap() bool { return a != nil && a.Type != nil && a.Type.Kind == KindMap }

type Block struct {
	Attributes map[string]*Attribute
	BlockTypes map[string]*BlockType
}

func (b *Block) Attr(name string) (*Attribute, bool) {
	if b == nil {
		return nil, false
	}
	a, ok := b.Attributes[name]
	return a, ok
}

func (b *Block) NestedBlock(name string) (*BlockType, bool) {
	if b == nil {
		return nil, false
	}
	bt, ok := b.BlockTypes[name]
	return bt, ok
}

func (b *Block) Has(name string) bool {
	if b == nil {
		return false
	}
	if _, ok := b.Attributes[name]; ok {
		return true
	}
	_, ok := b.BlockTypes[name]
	return ok
}

type BlockType struct {
	NestingMode string // "single" | "list" | "set" | "map"
	MinItems    int
	MaxItems    int
	Block       *Block
}

type Schema struct {
	Resources map[string]*Block
}

func (s *Schema) Resource(tfType string) (*Block, bool) {
	b, ok := s.Resources[tfType]
	return b, ok
}

var (
	loadOnce sync.Once
	loaded   *Schema
	loadErr  error
)

func Load() (*Schema, error) {
	loadOnce.Do(func() { loaded, loadErr = decode(embedded) })
	return loaded, loadErr
}

type wireRoot struct {
	ResourceSchemas map[string]wireBlock `json:"resource_schemas"`
}

type wireBlock struct {
	Attributes map[string]wireAttr      `json:"attributes"`
	BlockTypes map[string]wireBlockType `json:"block_types"`
}

type wireAttr struct {
	Type       json.RawMessage `json:"type"`
	Required   bool            `json:"required"`
	Optional   bool            `json:"optional"`
	Computed   bool            `json:"computed"`
	NestedType *struct {
		NestingMode string    `json:"nesting_mode"`
		Block       wireBlock `json:"block"`
	} `json:"nested_type"`
}

type wireBlockType struct {
	NestingMode string    `json:"nesting_mode"`
	MinItems    int       `json:"min_items"`
	MaxItems    int       `json:"max_items"`
	Block       wireBlock `json:"block"`
}

func decode(gz []byte) (*Schema, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("schema gzip: %w", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("schema read: %w", err)
	}
	var root wireRoot
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("schema json: %w", err)
	}
	s := &Schema{Resources: make(map[string]*Block, len(root.ResourceSchemas))}
	for name, wb := range root.ResourceSchemas {
		s.Resources[name] = convBlock(wb)
	}
	return s, nil
}

func convBlock(wb wireBlock) *Block {
	b := &Block{}
	if len(wb.Attributes) > 0 {
		b.Attributes = make(map[string]*Attribute, len(wb.Attributes))
		for name, wa := range wb.Attributes {
			a := &Attribute{
				Type:     parseCtyType(wa.Type),
				Required: wa.Required,
				Optional: wa.Optional,
				Computed: wa.Computed,
			}
			if wa.NestedType != nil {
				a.NestedMode = wa.NestedType.NestingMode
				a.Nested = convBlock(wa.NestedType.Block)
			}
			b.Attributes[name] = a
		}
	}
	if len(wb.BlockTypes) > 0 {
		b.BlockTypes = make(map[string]*BlockType, len(wb.BlockTypes))
		for name, wbt := range wb.BlockTypes {
			b.BlockTypes[name] = &BlockType{
				NestingMode: wbt.NestingMode,
				MinItems:    wbt.MinItems,
				MaxItems:    wbt.MaxItems,
				Block:       convBlock(wbt.Block),
			}
		}
	}
	return b
}

// parseCtyType decodes a JSON-encoded cty type.
func parseCtyType(raw json.RawMessage) *Type {
	if len(raw) == 0 {
		return &Type{Kind: KindDynamic}
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch s {
		case "number":
			return &Type{Kind: KindNumber}
		case "bool":
			return &Type{Kind: KindBool}
		case "dynamic":
			return &Type{Kind: KindDynamic}
		default:
			return &Type{Kind: KindString}
		}
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil || len(arr) < 2 {
		return &Type{Kind: KindDynamic}
	}
	var tag string
	_ = json.Unmarshal(arr[0], &tag)
	switch tag {
	case "list":
		return &Type{Kind: KindList, Elem: parseCtyType(arr[1])}
	case "set":
		return &Type{Kind: KindSet, Elem: parseCtyType(arr[1])}
	case "map":
		return &Type{Kind: KindMap, Elem: parseCtyType(arr[1])}
	case "object":
		var m map[string]json.RawMessage
		_ = json.Unmarshal(arr[1], &m)
		t := &Type{Kind: KindObject, Attrs: make(map[string]*Type, len(m))}
		for k, v := range m {
			t.Attrs[k] = parseCtyType(v)
		}
		return t
	case "tuple":
		return &Type{Kind: KindTuple}
	default:
		return &Type{Kind: KindDynamic}
	}
}
