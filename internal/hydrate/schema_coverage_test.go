package hydrate

import "testing"

// Every emittable type must exist in the schema.
func TestEmittableTypesHaveSchema(t *testing.T) {
	// direct hydrators
	for tf := range registry {
		if _, err := schemaFor(tf); err != nil {
			t.Errorf("hydrator %s: %v", tf, err)
		}
	}
	for _, tf := range arnToTF {
		if _, err := schemaFor(tf); err != nil {
			t.Errorf("arnToTF %s: %v", tf, err)
		}
	}
	// fanout children, gap-filled types and the wafv2 special-cases
	for _, tf := range append(append([]string{}, extraCoveredTypes...), wafv2SwitchTypes...) {
		if _, err := schemaFor(tf); err != nil {
			t.Errorf("extra covered type %s: %v", tf, err)
		}
	}
}
