package hydrate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
)

// Engine-specific settings map onto the schema almost entirely by SDK field
// name -- the one thing that breaks it is nameconv.Snake mishandling
// MySQL/MongoDb/PostgreSQL (MySQLSettings -> my_sql_settings instead of
// mysql_settings, MongoDbSettings -> mongo_db_settings instead of
// mongodb_settings, PostgreSQLSettings -> postgre_sql_settings instead of
// postgres_settings).
func TestDMSEndpointSettingsShape(t *testing.T) {
	sch, err := schemaFor("aws_dms_endpoint")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		val  any
	}{
		{"mysql_settings", &dmstypes.MySQLSettings{ServerTimezone: aws.String("UTC")}},
		{"postgres_settings", &dmstypes.PostgreSQLSettings{SlotName: aws.String("slot1")}},
		{"mongodb_settings", &dmstypes.MongoDbSettings{AuthType: dmstypes.AuthTypeValueNo}},
	}
	for _, c := range cases {
		nb, ok := sch.NestedBlock(c.name)
		if !ok {
			t.Fatalf("%s: schema block not found", c.name)
		}
		cfg, err := Generic(c.val, nb.Block, nil)
		if err != nil {
			t.Fatalf("%s: Generic error: %v", c.name, err)
		}
		if len(cfg) == 0 {
			t.Errorf("%s: dropped entirely (the MySQL/MongoDb/PostgreSQL acronym bug)", c.name)
		}
	}
}
