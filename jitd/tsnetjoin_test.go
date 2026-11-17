package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"tailscale.com/tsnet"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestFederatedJoin(t *testing.T) {
	tokFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokFile, []byte("jwt-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		env     map[string]string
		want    bool
		wantJWT string
		wantErr bool
	}{
		{name: "nothing set", env: nil},
		{name: "client id only", env: map[string]string{"TS_OAUTH_CLIENT_ID": "cid"}},
		{name: "auth key wins", env: map[string]string{"TS_AUTHKEY": "tskey-auth-x", "TS_OAUTH_CLIENT_ID": "cid", "TS_ID_TOKEN": "jwt"}},
		{name: "oauth client wins", env: map[string]string{"TS_OAUTH_CLIENT_SECRET": "s", "TS_OAUTH_CLIENT_ID": "cid", "TS_ID_TOKEN": "jwt"}},
		{name: "inline token", env: map[string]string{"TS_OAUTH_CLIENT_ID": "cid", "TS_ID_TOKEN": "jwt"}, want: true, wantJWT: "jwt"},
		{name: "token file", env: map[string]string{"TS_OAUTH_CLIENT_ID": "cid", "TS_ID_TOKEN": "file:" + tokFile}, want: true, wantJWT: "jwt-from-file"},
		{name: "missing token file", env: map[string]string{"TS_OAUTH_CLIENT_ID": "cid", "TS_ID_TOKEN": "file:" + tokFile + ".nope"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &tsnet.Server{Dir: t.TempDir()}
			got, err := federatedJoin(srv, "tag:jit", envOf(tc.env))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("federatedJoin = %v, want %v", got, tc.want)
			}
			if !tc.want {
				if srv.ClientID != "" || srv.IDToken != "" || srv.AdvertiseTags != nil {
					t.Fatalf("server changed: %+v", srv)
				}
				return
			}
			if srv.ClientID != "cid?ephemeral=false&preauthorized=true" {
				t.Errorf("ClientID = %q", srv.ClientID)
			}
			if srv.IDToken != tc.wantJWT {
				t.Errorf("IDToken = %q, want %q", srv.IDToken, tc.wantJWT)
			}
			if !slices.Equal(srv.AdvertiseTags, []string{"tag:jit"}) {
				t.Errorf("AdvertiseTags = %v", srv.AdvertiseTags)
			}
		})
	}
}

func TestWithoutEnv(t *testing.T) {
	t.Setenv("JITD_TEST_HIDDEN", "file:/token")
	got, err := withoutEnv([]string{"JITD_TEST_HIDDEN", "JITD_TEST_UNSET"}, func() (string, error) {
		if _, set := os.LookupEnv("JITD_TEST_UNSET"); set {
			t.Error("JITD_TEST_UNSET is set")
		}
		return os.Getenv("JITD_TEST_HIDDEN"), nil
	})
	if err != nil || got != "" {
		t.Fatalf("inside: %q, %v; want the variable unset", got, err)
	}
	if v := os.Getenv("JITD_TEST_HIDDEN"); v != "file:/token" {
		t.Fatalf("after: %q, want it set back", v)
	}
	if _, set := os.LookupEnv("JITD_TEST_UNSET"); set {
		t.Fatal("JITD_TEST_UNSET was set afterwards")
	}
}
