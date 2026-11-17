package main

import (
	"os"

	_ "tailscale.com/feature/identityfederation"
	"tailscale.com/tsnet"

	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// federatedJoin lets jitd's node join the tailnet through the same
// federated identity it uses for the Tailscale API (TS_OAUTH_CLIENT_ID with
// TS_ID_TOKEN), so no auth key is needed either. tsnet exchanges the ID
// token for a single-use auth key tagged tag, which needs the federated
// identity to have the auth_keys scope and tag.
//
// It applies on every start, not only the first. tsnet uses the auth key
// only when the node has to log in: a new node, or one whose key expired or
// that was logged out, which then rejoins by itself; a running node ignores
// it. And the node always advertises tag: starting without it would ask the
// control server to drop the tag, which logs a tagged node out.
//
// It does nothing when an auth key is set, when an OAuth client secret is
// set (the OAuth client is used for the API then, and has no ID token), or
// without a client ID and ID token.
//
// It returns whether the node joins that way.
func federatedJoin(srv *tsnet.Server, tag string, getenv func(string) string) (bool, error) {
	if getenv("TS_AUTHKEY") != "" || getenv("TS_AUTH_KEY") != "" || getenv("TS_OAUTH_CLIENT_SECRET") != "" {
		return false, nil
	}
	id, tok := getenv("TS_OAUTH_CLIENT_ID"), getenv("TS_ID_TOKEN")
	if id == "" || tok == "" {
		return false, nil
	}
	jwt, err := tsapi.ReadIDToken(tok)
	if err != nil {
		return false, err
	}
	// A server: not ephemeral, so it outlives restarts, and preauthorized,
	// for tailnets with device approval.
	srv.ClientID = id + "?ephemeral=false&preauthorized=true"
	srv.IDToken = jwt
	srv.AdvertiseTags = []string{tag}
	return true, nil
}

// withoutEnv runs fn with the variables keys unset, and sets them back
// afterwards. It changes the process environment, so only call it while
// nothing else runs.
func withoutEnv[T any](keys []string, fn func() (T, error)) (T, error) {
	for _, k := range keys {
		if v, set := os.LookupEnv(k); set {
			os.Unsetenv(k)
			defer os.Setenv(k, v)
		}
	}
	return fn()
}
