package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"

	"github.com/virtualbeck/inherit/internal/redact"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_transfer_host_key", hydrateTransferHostKey)
}

// r.ID is serverID/hostKeyID.
func hydrateTransferHostKey(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	serverID, keyID, ok := strings.Cut(r.ID, "/")
	if !ok {
		return nil, fmt.Errorf("unexpected host key id %q, expected serverID/hostKeyID", r.ID)
	}
	out, err := transfer.NewFromConfig(c.Cfg(r.Region)).DescribeHostKey(ctx, &transfer.DescribeHostKeyInput{ServerId: &serverID, HostKeyId: &keyID})
	if err != nil {
		return nil, err
	}
	if out.HostKey == nil {
		return nil, fmt.Errorf("not found")
	}
	return transferHostKeyConfig(serverID, *out.HostKey), nil
}

// The provider requires the private key body, which AWS never returns; the redaction placeholder puts it under ignore_changes.
func transferHostKeyConfig(serverID string, hk transfertypes.DescribedHostKey) map[string]any {
	cfg := map[string]any{"server_id": serverID, "host_key_body": redact.Sentinel}
	if d := aws.ToString(hk.Description); d != "" {
		cfg["description"] = d
	}
	return cfg
}
