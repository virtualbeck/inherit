package hydrate

import "testing"

func TestDatasyncS3BucketARNAndSubdir(t *testing.T) {
	cases := []struct {
		uri        string
		wantARN    string
		wantSubdir string
		wantOK     bool
	}{
		{"s3://my-bucket/some/path", "arn:aws:s3:::my-bucket", "/some/path", true},
		{"s3://my-bucket/", "arn:aws:s3:::my-bucket", "/", true},
		{"s3://my-bucket", "", "", false}, // no subdirectory segment at all -- can't happen for a real DataSync S3 location, but must not panic
		{"efs://fs-123/path", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		arn, subdir, ok := datasyncS3BucketARNAndSubdir(c.uri)
		if ok != c.wantOK || arn != c.wantARN || subdir != c.wantSubdir {
			t.Errorf("datasyncS3BucketARNAndSubdir(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.uri, arn, subdir, ok, c.wantARN, c.wantSubdir, c.wantOK)
		}
	}
}
