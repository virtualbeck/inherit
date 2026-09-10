// Package tfschema exposes the vendored AWS Terraform provider schema: for any
// aws_* resource type, whether a name is an argument or a nested block, its cty
// type, and its required/optional/computed flags. This is what lets the emitter
// pick `name = {...}` vs `name {...}` correctly for every attribute.
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

// Kind is the coarse shape of a cty type.
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

// Type is a decoded cty type.
type Type struct {
	Kind  Kind
	Elem  *Type            // list / set / map element
	Attrs map[string]*Type // object attributes
}

// IsCollectionOfObject reports a list/set whose element is an object, the shape
// the provider models as a repeatable nested block.
func (t *Type) IsCollectionOfObject() bool {
	return t != nil && (t.Kind == KindList || t.Kind == KindSet) && t.Elem != nil && t.Elem.Kind == KindObject
}

// Attribute is one schema attribute.
type Attribute struct {
	Type       *Type
	Required   bool
	Optional   bool
	Computed   bool
	NestedMode string // set when the provider models this attribute as a nested type
	Nested     *Block
}

// Settable reports whether a value for this attribute may appear in config
// (i.e. it isn't a purely computed / read-only attribute like id or arn).
func (a *Attribute) Settable() bool { return a != nil && (a.Optional || a.Required) }

// IsMap reports a map-typed attribute, emitted as `name = { ... }`.
func (a *Attribute) IsMap() bool { return a != nil && a.Type != nil && a.Type.Kind == KindMap }

// Block is a schema block: its direct attributes and nested block types.
type Block struct {
	Attributes map[string]*Attribute
	BlockTypes map[string]*BlockType
}

// Attr returns a direct attribute of the block.
func (b *Block) Attr(name string) (*Attribute, bool) {
	if b == nil {
		return nil, false
	}
	a, ok := b.Attributes[name]
	return a, ok
}

// NestedBlock returns a nested block type of the block.
func (b *Block) NestedBlock(name string) (*BlockType, bool) {
	if b == nil {
		return nil, false
	}
	bt, ok := b.BlockTypes[name]
	return bt, ok
}

// Has reports whether name is known to this block, as an attribute or a block.
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

// BlockType is a nested block definition.
type BlockType struct {
	NestingMode string // "single" | "list" | "set" | "map"
	MinItems    int
	MaxItems    int
	Block       *Block
}

// Schema is the whole provider's resource schema set.
type Schema struct {
	Resources map[string]*Block
}

// Resource returns the schema block for an aws_* resource type.
func (s *Schema) Resource(tfType string) (*Block, bool) {
	b, ok := s.Resources[tfType]
	return b, ok
}

var (
	loadOnce sync.Once
	loaded   *Schema
	loadErr  error
)

// Load decodes the embedded schema once and caches it.
func Load() (*Schema, error) {
	loadOnce.Do(func() { loaded, loadErr = decode(embedded) })
	return loaded, loadErr
}

// --- wire format ----------------------------------------------------------

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

// parseCtyType decodes the JSON encoding of a cty type:
//
//	"string" | "number" | "bool" | "dynamic"
//	["list", T] | ["set", T] | ["map", T]
//	["object", {name: T, ...}] (optionally a 3rd element listing optional names)
//	["tuple", [T, ...]]
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
