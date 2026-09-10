package hydrate

import "testing"

// Every TF type inherit can emit must exist in the vendored provider schema, or
// the emitter silently drops it.
func TestEmittableTypesHaveSchema(t *testing.T) {
	// direct hydrators
	for tf := range registry {
		if _, err := schemaFor(tf); err != nil {
			t.Errorf("hydrator %s: %v", tf, err)
		}
	}
	// arn -> tf mappings (a hydrator may land later, but the type must be real)
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
