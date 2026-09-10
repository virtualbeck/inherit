package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_transfer_agreement", hydrateTransferAgreement)
	register("aws_transfer_connector", hydrateTransferConnector)
	register("aws_transfer_certificate", hydrateTransferCertificate)
	register("aws_transfer_profile", hydrateTransferProfile)
}

// hydrateTransferAgreement's r.ID arrives as "serverID/agreementID" --
// discover.go's ARN splitting already leaves it in exactly this shape
// (confirmed against the real provider's own import id, which uses the
// identical "/" join), so no extra parsing beyond a single split is needed.
func hydrateTransferAgreement(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	serverID, agreementID, ok := strings.Cut(r.ID, "/")
	if !ok {
		return nil, fmt.Errorf("unexpected agreement id %q, expected serverID/agreementID", r.ID)
	}
	out, err := transfer.NewFromConfig(c.Cfg(r.Region)).DescribeAgreement(ctx, &transfer.DescribeAgreementInput{ServerId: &serverID, AgreementId: &agreementID})
	if err != nil {
		return nil, err
	}
	a := out.Agreement
	if a == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{
		"server_id":          serverID,
		"access_role":        aws.ToString(a.AccessRole),
		"base_directory":     aws.ToString(a.BaseDirectory),
		"local_profile_id":   aws.ToString(a.LocalProfileId),
		"partner_profile_id": aws.ToString(a.PartnerProfileId),
	}
	if v := aws.ToString(a.Description); v != "" {
		cfg["description"] = v
	}
	return cfg, nil
}

func hydrateTransferConnector(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	cl := transfer.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeConnector(ctx, &transfer.DescribeConnectorInput{ConnectorId: &id})
	if err != nil {
		return nil, err
	}
	conn := out.Connector
	if conn == nil {
		return nil, fmt.Errorf("not found")
	}
	sch, serr := schemaFor("aws_transfer_connector")
	var cfg map[string]any
	if serr == nil {
		cfg, _ = Generic(conn, sch, nil)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	cfg["access_role"] = aws.ToString(conn.AccessRole)
	if v := aws.ToString(conn.Url); v != "" {
		cfg["url"] = v
	}
	if v := aws.ToString(conn.LoggingRole); v != "" {
		cfg["logging_role"] = v
	}
	if v := aws.ToString(conn.SecurityPolicyName); v != "" {
		cfg["security_policy_name"] = v
	}
	return cfg, nil
}

func hydrateTransferCertificate(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := transfer.NewFromConfig(c.Cfg(r.Region)).DescribeCertificate(ctx, &transfer.DescribeCertificateInput{CertificateId: &id})
	if err != nil {
		return nil, err
	}
	cert := out.Certificate
	if cert == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{
		"usage":       "SIGNING",
		"certificate": aws.ToString(cert.Certificate),
	}
	if v := string(cert.Usage); v != "" {
		cfg["usage"] = v
	}
	if v := aws.ToString(cert.CertificateChain); v != "" {
		cfg["certificate_chain"] = v
	}
	if v := aws.ToString(cert.Description); v != "" {
		cfg["description"] = v
	}
	return cfg, nil
}

func hydrateTransferProfile(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := transfer.NewFromConfig(c.Cfg(r.Region)).DescribeProfile(ctx, &transfer.DescribeProfileInput{ProfileId: &id})
	if err != nil {
		return nil, err
	}
	p := out.Profile
	if p == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{
		"as2_id":       aws.ToString(p.As2Id),
		"profile_type": string(p.ProfileType),
	}
	if len(p.CertificateIds) > 0 {
		cfg["certificate_ids"] = toAny(p.CertificateIds)
	}
	return cfg, nil
}
