package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_transfer_user", hydrateTransferUser)
	registerFanout("aws_transfer_user", fanoutTransferSSHKeys)
}

var transferUserGeneric = genericHydratorOverride("aws_transfer_user", fetchTransferUser, nil)

func hydrateTransferUser(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cfg, err := transferUserGeneric(ctx, c, r)
	if err != nil || cfg == nil {
		return cfg, err
	}
	return transferUserConfig(cfg, r)
}

// DescribeUser's payload has no server ID, but the provider requires it.
func transferUserConfig(cfg map[string]any, r model.Resource) (map[string]any, error) {
	serverID, _, ok := transferUserIDs(r.ID)
	if !ok {
		return nil, fmt.Errorf("unexpected transfer user id %q, expected serverID/userName", r.ID)
	}
	cfg["server_id"] = serverID
	return cfg, nil
}

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

// DescribeUser already carries the keys.
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
