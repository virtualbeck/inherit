package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerGlobalGapFiller(gapFillIAMAccountSingletons)
	registerGlobalGapFiller(gapFillIAMUserCredentials)
}

// gapFillIAMAccountSingletons discovers the account-wide password policy
// and account alias -- both true account singletons (no ARN, no tagging
// concept, at most one of each per account).
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

// gapFillIAMUserCredentials discovers per-user access keys and X.509
// signing certificates, plus account-wide virtual MFA devices. secret/
// encrypted_secret/base_32_string_seed/qr_code_png are all Computed-only,
// create-time-only fields no Read/List call ever returns again -- left
// unset here, same structural gap as ACM's private key or the KMS key
// material itself, but harmless since none of them are Required.
// aws_iam_server_certificate is deliberately NOT attempted: its
// private_key is Required with zero Read equivalent at all (unlike the
// Computed fields here), the same unfixable class as aws_lb_trust_store.
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
			// serial_number is an ARN, "arn:aws:iam::account:mfa/[path/]name" --
			// the device's own name is the last "/"-separated segment
			// (confirmed against the real provider's parseVirtualMFADeviceARN).
			name := serial
			if i := strings.LastIndex(serial, "/"); i >= 0 {
				name = serial[i+1:]
			}
			if name == "" {
				continue
			}
			cfg := map[string]any{"virtual_mfa_device_name": name}
			// like ListRoles/ListUsers, ListVirtualMFADevices never
			// populates its own Tags field -- confirmed by a real fresh
			// import dropping every tag on this resource, not assumed.
			// Gap-filled resources skip the main hydrate loop's own
			// cfgMap["tags"] = r.Tags step entirely, so both r.Tags and
			// cfg["tags"] need setting here directly, same as the IAM
			// role/user/policy gap-filler.
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
