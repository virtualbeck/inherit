package hydrate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/virtualbeck/inherit/internal/nameconv"
	"github.com/virtualbeck/inherit/model"
	"github.com/virtualbeck/inherit/tfschema"
)

// tagKeys are handled from the discovery inventory, never from the SDK payload.
var tagKeys = map[string]bool{"tags": true, "tags_all": true, "tag_set": true, "tag_list": true}

// alwaysSkip are attribute names that are server-assigned identity even though
// the provider marks them optional+computed (so you *may* set them). Emitting
// them into generated config is always wrong.
var alwaysSkip = map[string]bool{
	"id": true, "arn": true, "unique_id": true, "owner_id": true,
}

// Generic turns an AWS SDK response value into a Terraform-attribute-shaped map:
// marshal -> snake-case keys -> apply per-resource key overrides -> keep only
// what the provider schema says is a settable argument or nested block, at every
// level of nesting. Purely computed attributes (id, arn, status, ...) fall away
// because the schema marks them computed-only.
func Generic(sdkVal any, block *tfschema.Block, overrides map[string]string) (map[string]any, error) {
	if block == nil {
		return nil, fmt.Errorf("nil schema block")
	}
	b, err := json.Marshal(sdkVal)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	return filterBlock(raw, block, overrides), nil
}

// filterBlock keeps only schema-known settable args/blocks. Keys are snake-cased
// here (not up front) so that the values of map(string) attributes -- tag maps,
// lambda environment variables, ssm parameters -- keep their original casing.
func filterBlock(m map[string]any, b *tfschema.Block, overrides map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for rawK, v := range m {
		k := nameconv.Snake(rawK)
		if to, ok := overrides[k]; ok {
			k = to
		}
		if tagKeys[k] || alwaysSkip[k] {
			continue
		}
		if a, ok := b.Attr(k); ok {
			if !a.Settable() {
				continue
			}
			switch {
			case a.Nested != nil:
				v = filterNested(v, a.Nested, a.NestedMode, overrides)
			case a.IsMap():
				// map(string) etc, pass the map through with its keys untouched
			default:
				// primitive, or list/set of primitives
			}
			if pruned, keep := prune(v); keep {
				out[k] = pruned
			}
			continue
		}
		if bt, ok := b.NestedBlock(k); ok {
			if pruned, keep := prune(filterNested(v, bt.Block, bt.NestingMode, overrides)); keep {
				out[k] = pruned
			}
			continue
		}
		// unknown to the schema, drop
	}
	return out
}

func filterNested(v any, block *tfschema.Block, mode string, overrides map[string]string) any {
	keep := func(m map[string]any) (map[string]any, bool) {
		fb := filterBlock(m, block, overrides)
		// a block we can't fill the required args of is never valid config
		return fb, len(fb) > 0 && blockRequiredMet(fb, block)
	}
	switch mode {
	case "single", "":
		switch t := v.(type) {
		case map[string]any:
			if fb, ok := keep(t); ok {
				return fb
			}
		case []any:
			if len(t) == 1 {
				if m, ok := t[0].(map[string]any); ok {
					if fb, ok := keep(m); ok {
						return fb
					}
				}
			}
		}
		return nil
	case "map":
		if t, ok := v.(map[string]any); ok {
			out := make(map[string]any, len(t))
			for k, e := range t {
				if m, ok := e.(map[string]any); ok {
					if fb, ok := keep(m); ok {
						out[k] = fb
					}
				}
			}
			return out
		}
		return nil
	default: // list, set
		switch t := v.(type) {
		case []any:
			out := make([]any, 0, len(t))
			for _, e := range t {
				if m, ok := e.(map[string]any); ok {
					if fb, ok := keep(m); ok {
						out = append(out, fb)
					}
				}
			}
			return out
		case map[string]any:
			// The provider models this as list/set nesting, but the SDK returns
			// a single object (e.g. aws_lambda_function.environment). Treat the
			// object as the one element.
			if fb, ok := keep(t); ok {
				return []any{fb}
			}
			return nil
		}
		return nil
	}
}

// blockRequiredMet reports whether every Required attribute of the block has a
// value in the filtered map.
func blockRequiredMet(m map[string]any, b *tfschema.Block) bool {
	if b == nil {
		return true
	}
	for name, a := range b.Attributes {
		if a.Required {
			if _, ok := m[name]; !ok {
				return false
			}
		}
	}
	return true
}

// toAny widens a []string to []any for a config map.
func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// prune drops values that carry no information: nil, "", empty map, empty slice.
// false and 0 are kept.
func prune(v any) (any, bool) {
	switch t := v.(type) {
	case nil:
		return nil, false
	case string:
		return t, t != ""
	case map[string]any:
		return t, len(t) > 0
	case []any:
		return t, len(t) > 0
	default:
		return v, true
	}
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

// genericHydrator wraps a "fetch one struct" func with the schema-filtered
// Generic mapping.
func genericHydrator(tfType string, fetch func(context.Context, *Clients, model.Resource) (any, error)) Hydrator {
	return genericHydratorOverride(tfType, fetch, nil)
}

// genericHydratorOverride is genericHydrator with per-resource key overrides
// (see Generic's overrides param) -- e.g. IAM's User/Group structs marshal
// to "user_name"/"group_name", which don't exist in the schema at all
// (aws_iam_user/aws_iam_group both just call the argument "name"); without
// the override Generic() drops the field entirely as unknown-to-schema,
// silently omitting a Required attribute.
func genericHydratorOverride(tfType string, fetch func(context.Context, *Clients, model.Resource) (any, error), overrides map[string]string) Hydrator {
	return func(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
		sch, err := schemaFor(tfType)
		if err != nil {
			return nil, err
		}
		v, err := fetch(ctx, c, r)
		if err != nil {
			return nil, err
		}
		return Generic(v, sch, overrides)
	}
}
