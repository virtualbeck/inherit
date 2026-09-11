package redact

import (
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

	// ECS container_definitions is left entirely untouched -- environment[]
	// isn't covered (see redact.go's package doc for why); a real secret
	// placed there instead of secrets[] is a mistake made outside this tool.
	if inv.Resources[4].Config["container_definitions"] != origECSContainerDefs {
		t.Errorf("ECS container_definitions should be untouched, got: %v", inv.Resources[4].Config["container_definitions"])
	}

	// every redacted value is recoverable from the secrets slice
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
			"tags":      map[string]string{"AKIAUAXEQOFYUKWCRPNJ": "label"},
		},
	}}}
	Split(inv)
	second := Split(inv)
	if len(second) != 0 {
		t.Errorf("second Split found %d secrets, want 0 (already redacted): %+v", len(second), second)
	}
}

// Confirmed against a real account: IAM users tagged with their own
// access key ID as the tag KEY (a common way to label "which key is
// this"), value a human description -- a location none of the
// field-specific rules cover, since it's not the value of any known-name
// field. Two redacted keys land in the SAME tags map, which is exactly
// the case that needs unique renamed keys or one silently clobbers the
// other.
func TestSplitRedactsAccessKeyIDsInTags(t *testing.T) {
	inv := &model.Inventory{Resources: []model.Resource{
		{
			ARN: "arn:aws:iam::1:user/read_only_all", TFType: "aws_iam_user",
			Config: map[string]any{
				"name": "read_only_all",
				"tags": map[string]string{
					"AKIAUAXEQOFYUKWCRPNJ": "testing_former2",
					"AKIAUAXEQOFYZMDPFH4O": "inherit_testing_read_only",
					"Environment":          "prod",
				},
			},
		},
		{
			ARN: "arn:aws:iam::1:user/virtualbeck", TFType: "aws_iam_user",
			Config: map[string]any{
				"name": "virtualbeck",
				"tags": map[string]string{"AKIAUAXEQOFYXSU27AD2": "virtualbeck_cli"},
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
	// The access key ID (the tag KEY) is the sensitive part and gets
	// renamed away; the human label (the tag VALUE -- "testing_former2")
	// isn't a credential and stays legible, unredacted, under its new key.
	redactedKeys := 0
	gotLabels := map[string]bool{}
	for k, v := range tags0 {
		if k == "Environment" {
			continue
		}
		redactedKeys++
		gotLabels[v] = true
		if k == "AKIAUAXEQOFYUKWCRPNJ" || k == "AKIAUAXEQOFYZMDPFH4O" {
			t.Errorf("original access-key-shaped tag key should not survive: %q", k)
		}
	}
	if redactedKeys != 2 {
		t.Errorf("want 2 renamed keys (one per redacted access key), got %d -- a key collision would silently drop one: %v", redactedKeys, tags0)
	}
	for _, want := range []string{"testing_former2", "inherit_testing_read_only"} {
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

	// the original access-key-shaped key is recoverable from the secrets slice
	var keySecrets int
	for _, s := range secrets {
		switch s.Value {
		case "AKIAUAXEQOFYUKWCRPNJ", "AKIAUAXEQOFYZMDPFH4O", "AKIAUAXEQOFYXSU27AD2":
			keySecrets++
		}
	}
	if keySecrets != 3 {
		t.Errorf("want 3 recovered access-key-shaped keys, got %d: %+v", keySecrets, secrets)
	}
}
