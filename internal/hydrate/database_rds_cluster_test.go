package hydrate

import "testing"

// The tagging API lists an Aurora cluster twice: by name and by its lowercased DbClusterResourceId.
func TestClusterResourceIDForm(t *testing.T) {
	for id, want := range map[string]string{
		"cluster-a1b2c3d4e5f6g7h8i9j0k1l2m3": "cluster-A1B2C3D4E5F6G7H8I9J0K1L2M3",
		"app-db":                             "",
		"cluster-short":                      "",
	} {
		got, ok := clusterResourceIDForm(id)
		if got != want || ok != (want != "") {
			t.Errorf("clusterResourceIDForm(%q) = %q, %v; want %q", id, got, ok, want)
		}
	}
}
