package redact

import (
	"encoding/json"
	"testing"

	"github.com/virtualbeck/inherit/model"
)

func TestSplit(t *testing.T) {
	inv := &model.Inventory{Resources: []model.Resource{
		{
			ARN: "arn:aws:lambda:us-east-1:1:function:f", TFType: "aws_lambda_function",
			Config: map[string]any{
				"environment": []any{map[string]any{"variables": map[string]any{
					"DB_URL": "postgres://user:pw@host/db", "LOG_LEVEL": "info",
				}}},
			},
		},
		{
			ARN: "arn:aws:ec2:us-east-1:1:instance/i-1", TFType: "aws_instance",
			Config: map[string]any{"user_data": "#!/bin/bash\nexport TOKEN=abc123"},
		},
		{
			ARN: "arn:aws:ssm:us-east-1:1:parameter/p", TFType: "aws_ssm_parameter",
			Config: map[string]any{"type": "String", "value": "super-secret"},
		},
		{
			ARN: "arn:aws:ssm:us-east-1:1:parameter/secure", TFType: "aws_ssm_parameter",
			Config: map[string]any{"type": "SecureString", "value": "REPLACE_ME"},
		},
		{
			ARN: "arn:aws:ecs:us-east-1:1:task-definition/t:1", TFType: "aws_ecs_task_definition",
			Config: map[string]any{"container_definitions": `[{"name":"web","environment":[{"name":"API_KEY","value":"k-live-xyz"}],"secrets":[{"name":"S","valueFrom":"arn:..."}]}]`},
		},
	}}
	origECSContainerDefs := inv.Resources[4].Config["container_definitions"]

	secrets := Split(inv)

	// lambda env values redacted, keys kept
	vars := inv.Resources[0].Config["environment"].([]any)[0].(map[string]any)["variables"].(map[string]any)
	if vars["DB_URL"] != Sentinel || vars["LOG_LEVEL"] != Sentinel {
		t.Errorf("lambda env not redacted: %v", vars)
	}
	if _, ok := vars["DB_URL"]; !ok {
		t.Error("lambda env key dropped, should be kept")
	}

	if inv.Resources[1].Config["user_data"] != Sentinel {
		t.Errorf("user_data not redacted: %v", inv.Resources[1].Config["user_data"])
	}

	// plain-String SSM redacted, SecureString untouched
	if inv.Resources[2].Config["value"] != Sentinel {
		t.Error("String SSM value not redacted")
	}
	if inv.Resources[3].Config["value"] != "REPLACE_ME" {
		t.Error("SecureString SSM value should not have been touched")
	}

	// environment[] is deliberately not redacted.
	if inv.Resources[4].Config["container_definitions"] != origECSContainerDefs {
		t.Errorf("ECS container_definitions should be untouched, got: %v", inv.Resources[4].Config["container_definitions"])
	}

	byPath := map[string]string{}
	for _, s := range secrets {
		byPath[s.ResourceARN+"|"+s.Path] = s.Value
	}
	want := map[string]string{
		"arn:aws:lambda:us-east-1:1:function:f|environment.variables.DB_URL":    "postgres://user:pw@host/db",
		"arn:aws:lambda:us-east-1:1:function:f|environment.variables.LOG_LEVEL": "info",
		"arn:aws:ec2:us-east-1:1:instance/i-1|user_data":                        "#!/bin/bash\nexport TOKEN=abc123",
		"arn:aws:ssm:us-east-1:1:parameter/p|value":                             "super-secret",
	}
	for k, v := range want {
		if byPath[k] != v {
			t.Errorf("secret %q = %q, want %q", k, byPath[k], v)
		}
	}
	if len(secrets) != len(want) {
		t.Errorf("got %d secrets, want %d -- ECS environment[] should never produce one: %+v", len(secrets), len(want), secrets)
	}
}

func TestSplitIdempotent(t *testing.T) {
	inv := &model.Inventory{Resources: []model.Resource{{
		ARN: "a", TFType: "aws_instance", Config: map[string]any{
			"user_data": "x",
			"tags":      map[string]string{"AKIAIOSFODNN7EXAMPLE": "label"},
		},
	}}}
	Split(inv)
	second := Split(inv)
	if len(second) != 0 {
		t.Errorf("second Split found %d secrets, want 0 (already redacted): %+v", len(second), second)
	}
}

// Two key IDs in one map mustn't collide.
func TestSplitRedactsAccessKeyIDsInTags(t *testing.T) {
	inv := &model.Inventory{Resources: []model.Resource{
		{
			ARN: "arn:aws:iam::1:user/read_only_all", TFType: "aws_iam_user",
			Config: map[string]any{
				"name": "read_only_all",
				"tags": map[string]string{
					"AKIAIOSFODNN7EXAMPLE": "ci_deploy_key",
					"AKIAI44QH8DHBEXAMPLE": "read_only_key",
					"Environment":          "prod",
				},
			},
		},
		{
			ARN: "arn:aws:iam::1:user/virtualbeck", TFType: "aws_iam_user",
			Config: map[string]any{
				"name": "virtualbeck",
				"tags": map[string]string{"AKIAJ7W2EXAMPLEKEY03": "virtualbeck_cli"},
			},
		},
	}}

	secrets := Split(inv)

	tags0, ok := inv.Resources[0].Config["tags"].(map[string]string)
	if !ok {
		t.Fatalf("tags map type changed: %T", inv.Resources[0].Config["tags"])
	}
	if len(tags0) != 3 {
		t.Fatalf("want 3 tags kept (2 redacted keys renamed, not dropped), got %d: %v", len(tags0), tags0)
	}
	if tags0["Environment"] != "prod" {
		t.Error("unrelated tag should be untouched")
	}
	// The key ID goes; the label value stays.
	redactedKeys := 0
	gotLabels := map[string]bool{}
	for k, v := range tags0 {
		if k == "Environment" {
			continue
		}
		redactedKeys++
		gotLabels[v] = true
		if k == "AKIAIOSFODNN7EXAMPLE" || k == "AKIAI44QH8DHBEXAMPLE" {
			t.Errorf("original access-key-shaped tag key should not survive: %q", k)
		}
	}
	if redactedKeys != 2 {
		t.Errorf("want 2 renamed keys (one per redacted access key), got %d -- a key collision would silently drop one: %v", redactedKeys, tags0)
	}
	for _, want := range []string{"ci_deploy_key", "read_only_key"} {
		if !gotLabels[want] {
			t.Errorf("human label %q should survive unredacted under the renamed key, got tags: %v", want, tags0)
		}
	}

	tags1 := inv.Resources[1].Config["tags"].(map[string]string)
	if len(tags1) != 1 {
		t.Fatalf("want 1 tag kept, got %d: %v", len(tags1), tags1)
	}
	for _, v := range tags1 {
		if v != "virtualbeck_cli" {
			t.Errorf("human label should survive unredacted, got %q", v)
		}
	}

	var keySecrets int
	for _, s := range secrets {
		switch s.Value {
		case "AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE", "AKIAJ7W2EXAMPLEKEY03":
			keySecrets++
		}
	}
	if keySecrets != 3 {
		t.Errorf("want 3 recovered access-key-shaped keys, got %d: %+v", keySecrets, secrets)
	}
}

// Same input, same output: no map-order churn.
func TestSplitDeterministic(t *testing.T) {
	mk := func() *model.Inventory {
		return &model.Inventory{Resources: []model.Resource{
			{
				ARN: "arn:aws:iam::1:user/u", TFType: "aws_iam_user",
				Config: map[string]any{"tags": map[string]string{
					"AKIAIOSFODNN7EXAMPLE": "a", "AKIAI44QH8DHBEXAMPLE": "b", "AKIAJ7W2EXAMPLEKEY03": "c",
				}},
			},
			{
				ARN: "arn:aws:lambda:us-east-1:1:function:f", TFType: "aws_lambda_function",
				Config: map[string]any{"environment": []any{map[string]any{"variables": map[string]any{
					"A": "1", "B": "2", "C": "3", "D": "4",
				}}}},
			},
			{
				ARN: "arn:aws:cloudformation:us-east-1:1:stack/s/x", TFType: "aws_cloudformation_stack",
				Config: map[string]any{"parameters": map[string]any{"P1": "x", "P2": "y", "P3": "z"}},
			},
		}}
	}
	snap := func() string {
		inv := mk()
		b, err := json.Marshal([]any{Split(inv), inv})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	want := snap()
	for range 50 {
		if got := snap(); got != want {
			t.Fatalf("output changed between runs:\n%s\n%s", want, got)
		}
	}
}
