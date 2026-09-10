package hydrate

import "testing"

func TestFixSelfManagedEndpoints(t *testing.T) {
	// GetEventSourceMappingConfiguration returns
	// self_managed_event_source.endpoints as map[string][]string (a list of
	// bootstrap servers per key), but the schema wants map(string) -- one
	// comma-joined string per key, matching how the provider itself expects
	// it in config.
	cfg := map[string]any{
		"self_managed_event_source": []any{
			map[string]any{
				"endpoints": map[string]any{
					"KAFKA_BOOTSTRAP_SERVERS": []any{"broker1:9092", "broker2:9092"},
				},
			},
		},
	}
	fixSelfManagedEndpoints(cfg)

	sms := cfg["self_managed_event_source"].([]any)
	ep := sms[0].(map[string]any)["endpoints"].(map[string]any)
	got, ok := ep["KAFKA_BOOTSTRAP_SERVERS"].(string)
	if !ok {
		t.Fatalf("endpoints[KAFKA_BOOTSTRAP_SERVERS] = %#v (%T), want a joined string", ep["KAFKA_BOOTSTRAP_SERVERS"], ep["KAFKA_BOOTSTRAP_SERVERS"])
	}
	if want := "broker1:9092,broker2:9092"; got != want {
		t.Errorf("endpoints[KAFKA_BOOTSTRAP_SERVERS] = %q, want %q", got, want)
	}
}

func TestFixSelfManagedEndpointsNoOpWhenAbsent(t *testing.T) {
	// no self_managed_event_source at all (the common case, e.g. an SQS or
	// Kinesis event source mapping) must not panic or fabricate a block.
	cfg := map[string]any{"function_name": "arn:aws:lambda:us-east-1:1:function:f"}
	fixSelfManagedEndpoints(cfg)
	if _, ok := cfg["self_managed_event_source"]; ok {
		t.Error("fixSelfManagedEndpoints must not create self_managed_event_source when it wasn't already present")
	}
}
