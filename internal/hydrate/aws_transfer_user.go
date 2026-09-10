package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_transfer_user", genericHydratorOverride("aws_transfer_user", fetchTransferUser, nil))
	registerFanout("aws_transfer_user", fanoutTransferSSHKeys)
}

// transferUserIDs splits r.ID ("server-id/username", the ARN resource
// "user/server-id/username" minus its leading "user/" segment) into the two
// separate values DescribeUser needs.
func transferUserIDs(id string) (serverID, userName string, ok bool) {
	serverID, userName, ok = strings.Cut(id, "/")
	return serverID, userName, ok && serverID != "" && userName != ""
}

func fetchTransferUser(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	serverID, userName, ok := transferUserIDs(r.ID)
	if !ok {
		return nil, nil
	}
	out, err := transfer.NewFromConfig(c.Cfg(r.Region)).DescribeUser(ctx, &transfer.DescribeUserInput{ServerId: &serverID, UserName: &userName})
	if err != nil {
		return nil, err
	}
	return out.User, nil
}

// fanoutTransferSSHKeys expands a user into its SSH public keys, a separate
// top-level resource in the provider -- DescribeUser's own response (already
// fetched by the parent hydrator, but fanouts don't see that result, so this
// re-fetches) already carries them, no separate API needed.
func fanoutTransferSSHKeys(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	serverID, userName, ok := transferUserIDs(parent.ID)
	if !ok {
		return nil, nil
	}
	out, err := transfer.NewFromConfig(c.Cfg(parent.Region)).DescribeUser(ctx, &transfer.DescribeUserInput{ServerId: &serverID, UserName: &userName})
	if err != nil || out.User == nil {
		return nil, err
	}
	var kids []model.Resource
	for _, k := range out.User.SshPublicKeys {
		keyID := aws.ToString(k.SshPublicKeyId)
		body := aws.ToString(k.SshPublicKeyBody)
		if keyID == "" || body == "" {
			continue
		}
		kids = append(kids, model.Resource{
			Service: "transfer", Type: "sshkey", TFType: "aws_transfer_ssh_key",
			Region: parent.Region, Account: parent.Account,
			ID: serverID + "/" + userName + "/" + keyID, ImportID: serverID + "/" + userName + "/" + keyID,
			Config: map[string]any{"server_id": serverID, "user_name": userName, "body": body},
		})
	}
	return kids, nil
}
