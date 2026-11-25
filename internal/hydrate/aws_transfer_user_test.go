package hydrate

import (
	"testing"

	"github.com/virtualbeck/inherit/model"
)

// DescribeUser's payload has no server ID, but the provider requires it.
func TestTransferUserConfigCarriesServerID(t *testing.T) {
	cfg, err := transferUserConfig(map[string]any{"user_name": "alice"}, model.Resource{ID: "s-1/alice"})
	if err != nil || cfg["server_id"] != "s-1" || cfg["user_name"] != "alice" {
		t.Errorf("transferUserConfig = %#v, %v", cfg, err)
	}
}
