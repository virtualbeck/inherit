package emit

import (
	"strings"
	"testing"

	"github.com/virtualbeck/inherit/model"
)

func TestRawNameLadder(t *testing.T) {
	cases := []struct {
		name string
		r    model.Resource
		sole bool
		want string
	}{
		{"sole of type -> main", model.Resource{ID: "vpc-0abc", TFType: "aws_vpc"}, true, "main"},
		{"sole beats a Name tag", model.Resource{ID: "vpc-0abc", TFType: "aws_vpc", Tags: map[string]string{"Name": "prod"}}, true, "main"},
		{"Name tag when not sole", model.Resource{ID: "x", TFType: "aws_vpc", Tags: map[string]string{"Name": "Prod Web SG"}}, false, "Prod_Web_SG"},
		{"SG heuristic from description", model.Resource{ID: "sg-1", TFType: "aws_security_group", Config: map[string]any{"description": "ssh from only smyrna ip address"}}, false, "sg_ssh"},
		{"SG heuristic https from port", model.Resource{ID: "sg-2", TFType: "aws_security_group", Config: map[string]any{"name": "allow-443"}}, false, "sg_https"},
		{"SG descriptive name attr, no heuristic hit", model.Resource{ID: "sg-3", TFType: "aws_security_group", Config: map[string]any{"name": "corp-internal"}}, false, "corp_internal"},
		{"SG opaque fallback", model.Resource{ID: "sg-0d3ebe25da01402e", TFType: "aws_security_group", Config: map[string]any{}}, false, "sg_" + shortHash("sg-0d3ebe25da01402e")},
		{"subnet public + az", model.Resource{ID: "subnet-1", TFType: "aws_subnet", Config: map[string]any{"availability_zone": "us-east-1a", "map_public_ip_on_launch": true}}, false, "public_1a"},
		{"subnet private default", model.Resource{ID: "subnet-2", TFType: "aws_subnet", Config: map[string]any{"availability_zone": "eu-west-1b"}}, false, "private_1b"},
		{"route table with igw route -> public", model.Resource{ID: "rtb-1", TFType: "aws_route_table", Config: map[string]any{"route": []any{map[string]any{"gateway_id": "igw-abc"}}}}, false, "public"},
		{"iam role by trust principal", model.Resource{ID: "MyCrypticRole", TFType: "aws_iam_role", Config: map[string]any{"assume_role_policy": `{"Statement":[{"Principal":{"Service":"lambda.amazonaws.com"}}]}`}}, false, "lambda"},
		{"cloudformation stack name from id", model.Resource{ID: "MyStack/abc-uuid", TFType: "aws_cloudformation_stack"}, false, "MyStack"},
		{"resourceexplorer2 index", model.Resource{ID: "b7d7-uuid", TFType: "aws_resourceexplorer2_index"}, false, "current"},
		{"non-opaque type: id trailing segment", model.Resource{ID: "arn:aws:iam::1:role/service-role/MyLambdaRole", TFType: "aws_iam_role"}, false, "MyLambdaRole"},
		{"sg rule https", model.Resource{ID: "sgr-1", TFType: "aws_vpc_security_group_ingress_rule", Config: map[string]any{"ip_protocol": "tcp", "from_port": float64(443), "to_port": float64(443)}}, false, "ingress_https"},
		{"sg rule egress all", model.Resource{ID: "sgr-2", TFType: "aws_vpc_security_group_egress_rule", Config: map[string]any{"ip_protocol": "-1"}}, false, "egress_all"},
		{"sg rule numeric tcp port", model.Resource{ID: "sgr-3", TFType: "aws_vpc_security_group_ingress_rule", Config: map[string]any{"ip_protocol": "tcp", "from_port": float64(5000), "to_port": float64(5000)}}, false, "ingress_5000"},
		{"sg rule udp range", model.Resource{ID: "sgr-4", TFType: "aws_vpc_security_group_ingress_rule", Config: map[string]any{"ip_protocol": "udp", "from_port": float64(32768), "to_port": float64(60999)}}, false, "ingress_32768_60999"},
		{"sg rule icmp no ports", model.Resource{ID: "sgr-5", TFType: "aws_vpc_security_group_ingress_rule", Config: map[string]any{"ip_protocol": "icmp"}}, false, "ingress_icmp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeName(rawName(c.r, c.sole)); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestClaimDedup(t *testing.T) {
	n := newNamer()
	mk := func() model.Resource {
		return model.Resource{TFType: "aws_subnet", Config: map[string]any{"availability_zone": "us-east-1a"}}
	}
	got := []string{n.claim(mk(), false), n.claim(mk(), false), n.claim(mk(), false)}
	want := []string{"private_1a", "private_1a_2", "private_1a_3"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedup[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestClaimNameLengthCap(t *testing.T) {
	long := "arn:aws:sns:us-west-1:178426410062:" + strings.Repeat("really-long-topic-name-", 6)
	got := newNamer().claim(model.Resource{ID: long}, false)
	if len(got) > maxLogicalName {
		t.Fatalf("name not capped: %d chars: %s", len(got), got)
	}
	if again := newNamer().claim(model.Resource{ID: long}, false); again != got {
		t.Fatalf("claim not stable: %q vs %q", got, again)
	}
}

func TestRawNameDeterministic(t *testing.T) {
	r := model.Resource{ID: "sg-0d3ebe25da01402e", TFType: "aws_security_group", Config: map[string]any{}}
	if a, b := rawName(r, false), rawName(r, false); a != b {
		t.Errorf("not deterministic: %q vs %q", a, b)
	}
}
