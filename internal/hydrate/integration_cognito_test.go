package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ciptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

func TestCognitoSchemaAttrs(t *testing.T) {
	// DescribeUserPool returns every attribute, including the ~20 built-in
	// standard ones every pool gets automatically. The real
	// terraform-provider-aws excludes a standard-named attribute from state
	// only when it exactly (reflect.DeepEqual) matches its own hardcoded
	// definition (cognitoStandardAttrs mirrors that table) -- so our config
	// must mirror the same test, not just "is this name in the standard
	// set" or "is this name short enough".
	attrs := []ciptypes.SchemaAttributeType{
		// exact match to the standard "email" shape -- the provider's Read
		// excludes this from state, so config must exclude it too.
		{Name: aws.String("email"), AttributeDataType: ciptypes.AttributeDataTypeString,
			Mutable: aws.Bool(true), Required: aws.Bool(false), DeveloperOnlyAttribute: aws.Bool(false),
			StringAttributeConstraints: &ciptypes.StringAttributeConstraintsType{
				MinLength: aws.String("0"), MaxLength: aws.String("2048"),
			}},
		// standard name, but Required: true -- doesn't match the standard
		// shape (which is Required: false), so the provider's Read does NOT
		// exclude it.
		{Name: aws.String("family_name"), AttributeDataType: ciptypes.AttributeDataTypeString,
			Mutable: aws.Bool(true), Required: aws.Bool(true), DeveloperOnlyAttribute: aws.Bool(false),
			StringAttributeConstraints: &ciptypes.StringAttributeConstraintsType{
				MinLength: aws.String("0"), MaxLength: aws.String("2048"),
			}},
		// exact match to the standard "phone_number_verified" shape --
		// excluded both by the standard-shape match and, if it somehow
		// weren't, by the 20-char cap (22 chars).
		{Name: aws.String("phone_number_verified"), AttributeDataType: ciptypes.AttributeDataTypeBoolean,
			Mutable: aws.Bool(true), Required: aws.Bool(false), DeveloperOnlyAttribute: aws.Bool(false)},
		{Name: aws.String("custom:tenant_id"), AttributeDataType: ciptypes.AttributeDataTypeString,
			Mutable: aws.Bool(true), Required: aws.Bool(false),
			StringAttributeConstraints: &ciptypes.StringAttributeConstraintsType{
				MinLength: aws.String("1"), MaxLength: aws.String("200"),
			}},
		{Name: aws.String("dev:internal_flag"), AttributeDataType: ciptypes.AttributeDataTypeBoolean,
			DeveloperOnlyAttribute: aws.Bool(true), Mutable: aws.Bool(false)},
	}

	got := cognitoSchemaAttrs(attrs)
	if len(got) != 3 {
		t.Fatalf("cognitoSchemaAttrs returned %d entries, want 3 (family_name, tenant_id, internal_flag; email and phone_number_verified excluded as exact standard-shape matches), got %+v", len(got), got)
	}

	byName := map[string]map[string]any{}
	for _, a := range got {
		m := a.(map[string]any)
		byName[m["name"].(string)] = m
	}

	tenant, ok := byName["tenant_id"]
	if !ok {
		t.Fatalf("expected a schema entry named %q (prefix stripped), got names %v", "tenant_id", keysOf(byName))
	}
	if tenant["name"] == "custom:tenant_id" {
		t.Error("the custom: prefix must be stripped -- the provider re-derives it from developer_only_attribute")
	}
	sc, ok := tenant["string_attribute_constraints"].(map[string]any)
	if !ok || sc["max_length"] != "200" {
		t.Errorf("tenant_id string_attribute_constraints = %v, want max_length 200", tenant["string_attribute_constraints"])
	}

	flag, ok := byName["internal_flag"]
	if !ok {
		t.Fatalf("expected a schema entry named %q (dev: prefix stripped), got names %v", "internal_flag", keysOf(byName))
	}
	if flag["developer_only_attribute"] != true {
		t.Errorf("internal_flag developer_only_attribute = %v, want true", flag["developer_only_attribute"])
	}

	if _, ok := byName["email"]; ok {
		t.Error("\"email\" exactly matches its standard shape and must not be redeclared -- the provider's Read excludes it from state")
	}
	if fam, ok := byName["family_name"]; !ok {
		t.Error("\"family_name\" with Required: true doesn't match the standard shape and must be declared to match state")
	} else if fam["required"] != true {
		t.Errorf("family_name required = %v, want true (must match the real observed value)", fam["required"])
	}
	if _, ok := byName["phone_number_verified"]; ok {
		t.Error("\"phone_number_verified\" exactly matches its standard shape (and also exceeds the 20-char cap) and must not be redeclared")
	}
}

func TestCognitoMatchesStandardAttr(t *testing.T) {
	// "identities" is a separate special case in the real provider (added by
	// a Cognito Identity Provider integration, not part of the main standard
	// table) but must be excluded the same way -- an empty
	// StringAttributeConstraints{}, not nil and not a populated one.
	identities := ciptypes.SchemaAttributeType{
		AttributeDataType: ciptypes.AttributeDataTypeString, DeveloperOnlyAttribute: aws.Bool(false),
		Mutable: aws.Bool(true), Required: aws.Bool(false), Name: aws.String("identities"),
		StringAttributeConstraints: &ciptypes.StringAttributeConstraintsType{},
	}
	if !cognitoMatchesStandardAttr(identities) {
		t.Error("identities with empty StringAttributeConstraints{} should match the standard/identities table")
	}
	identities.StringAttributeConstraints = nil
	if cognitoMatchesStandardAttr(identities) {
		t.Error("identities with nil StringAttributeConstraints should NOT match (real API always returns the empty struct, not nil)")
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
