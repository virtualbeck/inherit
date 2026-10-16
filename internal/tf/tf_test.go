package tf

import "testing"

func TestConciseSupported(t *testing.T) {
	for v, want := range map[string]bool{
		"OpenTofu v1.11.5\non linux_amd64\n": true,
		"OpenTofu v1.8.0\n":                  true,
		"OpenTofu v1.7.3\n":                  false,
		"OpenTofu v2.0.0-beta1\n":            true,
		"Terraform v1.9.8\non linux_amd64\n": false,
		"":                                   false,
	} {
		if got := conciseSupported(v); got != want {
			t.Errorf("conciseSupported(%q) = %v, want %v", v, got, want)
		}
	}
}
