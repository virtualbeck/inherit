package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerGlobalGapFiller(gapFillIAMAccountSingletons)
	registerGlobalGapFiller(gapFillIAMUserCredentials)
}

func gapFillIAMAccountSingletons(ctx context.Context, c *Clients, _ string) ([]model.Resource, error) {
	cl := iam.NewFromConfig(c.Cfg(""))
	var out []model.Resource

	if pp, err := cl.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{}); err == nil && pp.PasswordPolicy != nil {
		p := pp.PasswordPolicy
		cfg := map[string]any{"allow_users_to_change_password": p.AllowUsersToChangePassword}
		if p.HardExpiry != nil {
			cfg["hard_expiry"] = *p.HardExpiry
		}
		if p.MaxPasswordAge != nil {
			cfg["max_password_age"] = int(*p.MaxPasswordAge)
		}
		if p.MinimumPasswordLength != nil {
			cfg["minimum_password_length"] = int(*p.MinimumPasswordLength)
		}
		if p.PasswordReusePrevention != nil {
			cfg["password_reuse_prevention"] = int(*p.PasswordReusePrevention)
		}
		cfg["require_lowercase_characters"] = p.RequireLowercaseCharacters
		cfg["require_numbers"] = p.RequireNumbers
		cfg["require_symbols"] = p.RequireSymbols
		cfg["require_uppercase_characters"] = p.RequireUppercaseCharacters
		out = append(out, model.Resource{
			Service: "iam", Type: "account-password-policy", TFType: "aws_iam_account_password_policy",
			ID: "iam-account-password-policy", ImportID: "iam-account-password-policy",
			Config: cfg,
		})
	}

	if al, err := cl.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{}); err == nil && len(al.AccountAliases) > 0 {
		alias := al.AccountAliases[0]
		out = append(out, model.Resource{
			Service: "iam", Type: "account-alias", TFType: "aws_iam_account_alias",
			ID: alias, ImportID: alias,
			Config: map[string]any{"account_alias": alias},
		})
	}

	return out, nil
}

// Secrets are create-only; server certificates are skipped.
func gapFillIAMUserCredentials(ctx context.Context, c *Clients, _ string) ([]model.Resource, error) {
	cl := iam.NewFromConfig(c.Cfg(""))
	var out []model.Resource

	up := iam.NewListUsersPaginator(cl, &iam.ListUsersInput{})
	for up.HasMorePages() {
		page, err := up.NextPage(ctx)
		if err != nil {
			break
		}
		for _, u := range page.Users {
			userName := aws.ToString(u.UserName)
			if userName == "" {
				continue
			}

			if keys, err := cl.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: &userName}); err == nil {
				for _, k := range keys.AccessKeyMetadata {
					id := aws.ToString(k.AccessKeyId)
					if id == "" {
						continue
					}
					out = append(out, model.Resource{
						Service: "iam", Type: "access-key", TFType: "aws_iam_access_key",
						ID: id, ImportID: id,
						Config: map[string]any{
							"user":   userName,
							"status": string(k.Status),
						},
					})
				}
			}

			if certs, err := cl.ListSigningCertificates(ctx, &iam.ListSigningCertificatesInput{UserName: &userName}); err == nil {
				for _, cert := range certs.Certificates {
					certID := aws.ToString(cert.CertificateId)
					body := aws.ToString(cert.CertificateBody)
					if certID == "" || body == "" {
						continue
					}
					out = append(out, model.Resource{
						Service: "iam", Type: "signing-certificate", TFType: "aws_iam_signing_certificate",
						ID: certID + ":" + userName, ImportID: certID + ":" + userName,
						Config: map[string]any{
							"user_name":        userName,
							"certificate_body": body,
							"status":           string(cert.Status),
						},
					})
				}
			}
		}
	}

	mp := iam.NewListVirtualMFADevicesPaginator(cl, &iam.ListVirtualMFADevicesInput{})
	for mp.HasMorePages() {
		page, err := mp.NextPage(ctx)
		if err != nil {
			break
		}
		for _, d := range page.VirtualMFADevices {
			serial := aws.ToString(d.SerialNumber)
			if serial == "" {
				continue
			}
			// the device name ends the serial ARN
			name := serial
			if i := strings.LastIndex(serial, "/"); i >= 0 {
				name = serial[i+1:]
			}
			if name == "" {
				continue
			}
			cfg := map[string]any{"virtual_mfa_device_name": name}
			// List never returns tags; set them here
			var tags map[string]string
			if lt, terr := cl.ListMFADeviceTags(ctx, &iam.ListMFADeviceTagsInput{SerialNumber: &serial}); terr == nil {
				tags = iamTagMap(lt.Tags)
				if len(tags) > 0 {
					cfg["tags"] = tags
				}
			}
			out = append(out, model.Resource{
				Service: "iam", Type: "mfa", TFType: "aws_iam_virtual_mfa_device",
				ID: serial, ImportID: serial,
				Tags:   tags,
				Config: cfg,
			})
		}
	}

	return out, nil
}
