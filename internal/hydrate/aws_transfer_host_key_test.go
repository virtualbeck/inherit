package hydrate

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"

	"github.com/virtualbeck/inherit/internal/redact"
	"github.com/virtualbeck/inherit/model"
)

// Types a real account scan found unmapped that the provider schema supports.
func TestPilotUnmappedTypesResolve(t *testing.T) {
	for arn, want := range map[[2]string]string{
		{"transfer", "host-key"}: "aws_transfer_host_key",
	} {
		if got := ResolveTFType(model.Resource{Service: arn[0], Type: arn[1]}); got != want {
			t.Errorf("%v resolves to %q, want %q", arn, got, want)
		}
		if _, ok := registry[want]; !ok {
			t.Errorf("%s has no hydrator", want)
		}
	}
}

func TestTransferHostKeyConfig(t *testing.T) {
	got := transferHostKeyConfig("s-1", transfertypes.DescribedHostKey{Description: aws.String("rotated 2026")})
	want := map[string]any{"server_id": "s-1", "description": "rotated 2026", "host_key_body": redact.Sentinel}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("transferHostKeyConfig = %#v, want %#v", got, want)
	}
}
