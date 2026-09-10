package redact

import (
	"encoding/json"
	"testing"

	"github.com/virtualbeck/inherit-core/model"
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

	secrets := Split(inv)

	// lambda env values redacted, keys kept
	vars := inv.Resources[0].Config["environment"].([]any)[0].(map[string]any)["variables"].(map[string]any)
	if vars["DB_URL"] != Sentinel || vars["LOG_LEVEL"] != Sentinel {
		t.Errorf("lambda env not redacted: %v", vars)
	}
	if _, ok := vars["DB_URL"]; !ok {
		t.Error("lambda env key dropped, should be kept")
	}

	// user_data redacted
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

	// ECS container env value redacted, secrets[] untouched
	var containers []map[string]any
	if err := json.Unmarshal([]byte(inv.Resources[4].Config["container_definitions"].(string)), &containers); err != nil {
		t.Fatal(err)
	}
	env := containers[0]["environment"].([]any)[0].(map[string]any)
	if env["value"] != Sentinel {
		t.Errorf("ECS env value not redacted: %v", env)
	}
	if containers[0]["secrets"] == nil {
		t.Error("ECS secrets[] should be left alone")
	}

	// every redacted value is recoverable from the secrets slice
	byPath := map[string]string{}
	for _, s := range secrets {
		byPath[s.ResourceARN+"|"+s.Path] = s.Value
	}
	want := map[string]string{
		"arn:aws:lambda:us-east-1:1:function:f|environment.variables.DB_URL":                       "postgres://user:pw@host/db",
		"arn:aws:ec2:us-east-1:1:instance/i-1|user_data":                                           "#!/bin/bash\nexport TOKEN=abc123",
		"arn:aws:ssm:us-east-1:1:parameter/p|value":                                                "super-secret",
		"arn:aws:ecs:us-east-1:1:task-definition/t:1|container_definitions[0].environment.API_KEY": "k-live-xyz",
	}
	for k, v := range want {
		if byPath[k] != v {
			t.Errorf("secret %q = %q, want %q", k, byPath[k], v)
		}
	}
}

func TestSplitIdempotent(t *testing.T) {
	inv := &model.Inventory{Resources: []model.Resource{{
		ARN: "a", TFType: "aws_instance", Config: map[string]any{"user_data": "x"},
	}}}
	Split(inv)
	second := Split(inv)
	if len(second) != 0 {
		t.Errorf("second Split found %d secrets, want 0 (already redacted)", len(second))
	}
}
