package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	_ "tailscale.com/feature/identityfederation"
	"tailscale.com/tsnet"

	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// federatedJoin lets a new jitd node join the tailnet through the same
// federated identity it uses for the Tailscale API (TS_OAUTH_CLIENT_ID with
// TS_ID_TOKEN), so no auth key is needed either. tsnet exchanges the ID
// token for a one-off auth key tagged tag, which needs the federated
// identity to have the auth_keys scope and tag.
//
// It does nothing once the node has joined (it keeps its key in the state
// directory, and tsnet would otherwise mint a new auth key on every start),
// when an auth key is set, when an OAuth client secret is set (the OAuth
// client is used for the API then, and has no ID token), or without a client
// ID and ID token.
//
// It returns whether the node will join that way.
func federatedJoin(srv *tsnet.Server, tag string, getenv func(string) string) (bool, error) {
	if getenv("TS_AUTHKEY") != "" || getenv("TS_AUTH_KEY") != "" || getenv("TS_OAUTH_CLIENT_SECRET") != "" {
		return false, nil
	}
	if joined, err := nodeJoined(srv.Dir); err != nil || joined {
		return false, err
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

// nodeJoined reports whether the tsnet state in dir has a logged-in node.
// tailscaled saves the node's profile under "_profiles" only once it has
// logged in, so a node that only ever reached NeedsLogin has none.
func nodeJoined(dir string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, "tailscaled.state"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var state map[string][]byte
	if err := json.Unmarshal(b, &state); err != nil {
		return false, fmt.Errorf("reading %s: %w", filepath.Join(dir, "tailscaled.state"), err)
	}
	var profiles map[string]json.RawMessage
	if err := json.Unmarshal(state["_profiles"], &profiles); err != nil {
		return false, nil
	}
	return len(profiles) > 0, nil
}
