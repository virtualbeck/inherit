package emit

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/virtualbeck/inherit/model"
)

// stressTemplate is one resource of each of the ~30 most structurally
// diverse covered types (real nested blocks, cross-resource references,
// multi-region candidates), reused as a stamp: TestStressLargeInventory
// replicates it N times across many regions/accounts to build a synthetic
// inventory far larger than any account this project has actually been run
// against (the biggest real run on record is 524 resources). Templates use
// "%d" where a unique value is needed.
func stressTemplate() []model.Resource {
	return []model.Resource{
		{TFType: "aws_vpc", ID: "vpc-%d", Tags: map[string]string{"Name": "vpc-%d"},
			Config: map[string]any{"cidr_block": "10.%3d.0.0/16", "instance_tenancy": "default", "tags": map[string]string{"Name": "vpc-%d"}}},
		{TFType: "aws_subnet", ID: "subnet-%d",
			Config: map[string]any{"vpc_id": "vpc-%d", "cidr_block": "10.%3d.1.0/24", "availability_zone": "us-east-1a", "map_public_ip_on_launch": false}},
		{TFType: "aws_security_group", ID: "sg-%d",
			Config: map[string]any{"name": "sg-%d", "description": "web", "vpc_id": "vpc-%d"}},
		{TFType: "aws_route_table", ID: "rtb-%d",
			Config: map[string]any{"vpc_id": "vpc-%d", "route": []any{
				map[string]any{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-%d"},
			}}},
		{TFType: "aws_instance", ID: "i-%d",
			Config: map[string]any{"ami": "ami-abc123", "instance_type": "t3.micro", "subnet_id": "subnet-%d"}},
		{TFType: "aws_db_instance", ID: "db-%d",
			Config: map[string]any{
				"identifier": "db-%d", "engine": "postgres", "instance_class": "db.t3.micro",
				"allocated_storage": int32(20), "username": "admin", "skip_final_snapshot": true,
			}},
		{TFType: "aws_s3_bucket", ID: "bucket-%d",
			Config: map[string]any{"bucket": "bucket-%d"}},
		{TFType: "aws_s3_bucket_versioning", ID: "bucket-%d",
			Config: map[string]any{"bucket": "bucket-%d", "versioning_configuration": map[string]any{"status": "Enabled"}}},
		{TFType: "aws_s3_bucket_public_access_block", ID: "bucket-%d",
			Config: map[string]any{"bucket": "bucket-%d", "block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}},
		{TFType: "aws_lambda_function", ID: "fn-%d",
			Config: map[string]any{"function_name": "fn-%d", "handler": "index.handler", "runtime": "nodejs20.x", "role": "arn:aws:iam::%012d:role/lambda-role"}},
		{TFType: "aws_iam_role", ID: "role-%d",
			Config: map[string]any{"name": "role-%d", "assume_role_policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`}},
		{TFType: "aws_iam_policy", ID: "policy-%d",
			Config: map[string]any{"name": "policy-%d", "policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`}},
		{TFType: "aws_kms_key", ID: "key-%d",
			Config: map[string]any{"description": "key-%d"}},
		{TFType: "aws_sns_topic", ID: "topic-%d",
			Config: map[string]any{"name": "topic-%d"}},
		{TFType: "aws_sqs_queue", ID: "queue-%d",
			Config: map[string]any{"name": "queue-%d"}},
		{TFType: "aws_dynamodb_table", ID: "table-%d",
			Config: map[string]any{
				"name": "table-%d", "billing_mode": "PAY_PER_REQUEST", "hash_key": "id",
				"attribute": []any{map[string]any{"name": "id", "type": "S"}},
			}},
		{TFType: "aws_cloudwatch_log_group", ID: "/aws/lambda/fn-%d",
			Config: map[string]any{"name": "/aws/lambda/fn-%d"}},
		{TFType: "aws_cloudwatch_metric_alarm", ID: "alarm-%d",
			Config: map[string]any{
				"alarm_name": "alarm-%d", "comparison_operator": "GreaterThanThreshold", "evaluation_periods": int32(1),
				"metric_name": "Errors", "namespace": "AWS/Lambda", "period": int32(60), "statistic": "Sum", "threshold": float64(1),
				"dimensions": map[string]string{"FunctionName": "fn-%d"},
			}},
		{TFType: "aws_lb", ID: "lb-%d",
			Config: map[string]any{"name": "lb-%d", "internal": false, "load_balancer_type": "application", "subnets": []any{"subnet-%d"}}},
		{TFType: "aws_lb_target_group", ID: "tg-%d",
			Config: map[string]any{"name": "tg-%d", "port": int32(80), "protocol": "HTTP", "vpc_id": "vpc-%d"}},
		{TFType: "aws_lb_listener", ID: "listener-%d",
			Config: map[string]any{
				"load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:%012d:loadbalancer/app/lb-%d/x",
				"port":              int32(80), "protocol": "HTTP",
				"default_action": []any{map[string]any{"type": "forward", "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:%012d:targetgroup/tg-%d/x"}},
			}},
		{TFType: "aws_ecs_cluster", ID: "cluster-%d",
			Config: map[string]any{"name": "cluster-%d"}},
		{TFType: "aws_ecs_service", ID: "svc-%d",
			Config: map[string]any{"name": "svc-%d", "cluster": "cluster-%d", "desired_count": int32(1), "launch_type": "FARGATE"}},
		{TFType: "aws_route53_zone", ID: "Z%d",
			Config: map[string]any{"name": "zone%d.example.com"}},
		{TFType: "aws_secretsmanager_secret", ID: "secret-%d",
			Config: map[string]any{"name": "secret-%d"}},
		{TFType: "aws_ec2_transit_gateway_route_table", ID: "tgw-rtb-%d",
			Config: map[string]any{"transit_gateway_id": "tgw-%d"}},
		{TFType: "aws_ec2_transit_gateway_route", ID: "tgw-rtb-%d_10.0.0.0/16", ImportID: "tgw-rtb-%d_10.0.0.0/16",
			Config: map[string]any{"transit_gateway_route_table_id": "tgw-rtb-%d", "destination_cidr_block": "10.0.0.0/16", "blackhole": true}},
		{TFType: "aws_backup_selection", ID: "sel-%d", ImportID: "plan-%d|sel-%d",
			Config: map[string]any{"name": "sel-%d", "plan_id": "plan-%d", "iam_role_arn": "arn:aws:iam::%012d:role/backup"}},
		{TFType: "aws_guardduty_filter", ID: "detector-%d:filter-%d", ImportID: "detector-%d:filter-%d",
			Config: map[string]any{
				"name": "filter-%d", "detector_id": "detector-%d", "action": "ARCHIVE", "rank": int32(1),
				"finding_criteria": []any{map[string]any{"criterion": []any{map[string]any{"field": "severity", "greater_than": "7"}}}},
			}},
	}
}

// expand replaces every "%d" in a template's ID/ImportID/Tags/Config with n,
// and every "%012d" with a synthetic 12-digit account id, deep-copying maps
// and slices so replicas never alias each other's mutable state.
func expand(tpl model.Resource, region string, account string, n int) model.Resource {
	r := tpl
	r.Region = region
	r.Account = account
	r.ID = sprintfAll(tpl.ID, n)
	r.ImportID = sprintfAll(tpl.ImportID, n)
	if tpl.Tags != nil {
		r.Tags = map[string]string{}
		for k, v := range tpl.Tags {
			r.Tags[k] = sprintfAll(v, n)
		}
	}
	r.Config = expandValue(tpl.Config, n).(map[string]any)
	return r
}

func sprintfAll(s string, n int) string {
	if s == "" {
		return s
	}
	// crude but sufficient: replace the three placeholder shapes used above.
	// %3d must be handled before the generic %d pass (it's a prefix of it),
	// and produces a single valid IPv4 octet (0-255) for synthetic CIDRs --
	// the bare %d version overflowed past 255 at n>255 and every "tofu
	// validate" past the first ~255 resources failed on an invalid CIDR,
	// caught by this stress test's own first real run.
	out := s
	for {
		i := indexOf(out, "%012d")
		if i < 0 {
			break
		}
		out = out[:i] + fmt.Sprintf("%012d", n%1_000_000_000) + out[i+5:]
	}
	for {
		i := indexOf(out, "%3d")
		if i < 0 {
			break
		}
		out = out[:i] + strconv.Itoa(n%256) + out[i+3:]
	}
	for {
		i := indexOf(out, "%d")
		if i < 0 {
			break
		}
		out = out[:i] + strconv.Itoa(n) + out[i+2:]
	}
	return out
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func expandValue(v any, n int) any {
	switch t := v.(type) {
	case string:
		return sprintfAll(t, n)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = expandValue(val, n)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(t))
		for k, val := range t {
			out[k] = sprintfAll(val, n)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = expandValue(e, n)
		}
		return out
	default:
		return v
	}
}

// TestStressLargeInventory replicates stressTemplate across many synthetic
// resources and regions, timing emit.Write and (when tofu/terraform is on
// PATH) a real init+validate+plan against the result. Sizes are chosen to
// go well past the biggest account this project has actually seen (524
// resources) into territory nothing here has ever been run against.
// Skipped by default -- set INHERIT_STRESS=1 (needs INHERIT_INTEGRATION=1
// too for the tofu phase, since that needs a provider download/plugin cache).
func TestStressLargeInventory(t *testing.T) {
	if os.Getenv("INHERIT_STRESS") == "" {
		t.Skip("set INHERIT_STRESS=1 to run (writes large synthetic projects, can take a while)")
	}
	sizes := []int{1000, 5000, 15000}
	if v := os.Getenv("INHERIT_STRESS_SIZES"); v != "" {
		sizes = nil
		for _, p := range splitComma(v) {
			n, err := strconv.Atoi(p)
			if err != nil {
				t.Fatalf("bad INHERIT_STRESS_SIZES entry %q: %v", p, err)
			}
			sizes = append(sizes, n)
		}
	}

	regions := []string{"us-east-1", "us-west-2", "eu-west-1"}
	tpl := stressTemplate()
	runValidate := os.Getenv("INHERIT_INTEGRATION") != ""
	var bin string
	if runValidate {
		for _, b := range []string{"tofu", "terraform"} {
			if _, err := exec.LookPath(b); err == nil {
				bin = b
				break
			}
		}
		if bin == "" {
			runValidate = false
		}
	}

	for _, target := range sizes {
		t.Run(fmt.Sprintf("n=%d", target), func(t *testing.T) {
			replicas := target/len(tpl) + 1
			var resources []model.Resource
			n := 0
			for i := 0; i < replicas && len(resources) < target; i++ {
				region := regions[i%len(regions)]
				account := fmt.Sprintf("%012d", 100000000000+i%50) // 50 distinct accounts, like a real org
				for _, t := range tpl {
					if len(resources) >= target {
						break
					}
					n++
					resources = append(resources, expand(t, region, account, n))
				}
			}
			inv := model.Inventory{Account: "100000000000", Regions: regions, Resources: resources}

			var memBefore, memAfter runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&memBefore)

			dir := t.TempDir()
			start := time.Now()
			res, err := Write(inv, dir, Options{})
			writeElapsed := time.Since(start)
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			runtime.ReadMemStats(&memAfter)

			var fileCount int
			var totalBytes int64
			_ = filepathWalk(dir, func(size int64) { fileCount++; totalBytes += size })

			t.Logf("resources=%d  emit.Write=%s  files=%d  hcl_bytes=%d  heap_alloc_delta=%dMB  imports=%d  skipped=%d",
				len(resources), writeElapsed, fileCount, totalBytes,
				(memAfter.HeapAlloc-memBefore.HeapAlloc)/1024/1024, len(res.Imports), res.Skipped)

			if !runValidate {
				t.Log("tofu/terraform not on PATH or INHERIT_INTEGRATION unset -- skipping init/validate phase")
				return
			}

			// no further than validate: plan would need to resolve
			// data.aws_caller_identity.current (a real STS call) since
			// nearly every resource's ARN-embedded account id routes
			// through it -- validate doesn't evaluate data sources at all,
			// which is exactly why the existing integration test
			// (TestWriteTofuValidate) stops there too, not because plan
			// wasn't worth timing.
			run := func(name string, args ...string) time.Duration {
				t.Helper()
				cmd := exec.Command(bin, args...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "AWS_ACCESS_KEY_ID=x", "AWS_SECRET_ACCESS_KEY=x", "AWS_REGION=us-east-1")
				st := time.Now()
				out, err := cmd.CombinedOutput()
				el := time.Since(st)
				if err != nil {
					t.Fatalf("%s %v (%s): %v\n%s", bin, args, el, err, out)
				}
				return el
			}
			tInit := run("init", "init", "-backend=false", "-input=false", "-no-color")
			tValidate := run("validate", "validate", "-no-color")
			t.Logf("resources=%d  init=%s  validate=%s", len(resources), tInit, tValidate)
		})
	}
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func filepathWalk(dir string, fn func(size int64)) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := dir + "/" + e.Name()
		if e.IsDir() {
			_ = filepathWalk(p, fn)
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		fn(info.Size())
	}
	return nil
}
