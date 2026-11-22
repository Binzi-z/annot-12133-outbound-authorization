// Package authz defines the request authorization identity, its canonical
// fingerprint and the HMAC-SHA256 tokens that carry it over a mux stream.
//
// The identity is the tuple (Tenant, PolicyGeneration, OriginalName,
// ResolutionSource, ConnID, redirect Hops). Two requests that resolve to the
// same dial address but differ in ANY field have different fingerprints and
// different pool keys, so neither can borrow the other's trust context.
package authz

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
)

// Hop records one redirect that the request has traversed.
type Hop struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Address string `json:"address"` // actual address this hop connected to
}

// Identity is the full authorization identity of one request.
type Identity struct {
	Tenant           string `json:"tenant"`
	PolicyGeneration int64  `json:"policy_generation"`
	OriginalName     string `json:"original_name"`
	ResolutionSource string `json:"resolution_source"`
	Target           string `json:"target"` // dialed address produced by resolution
	ConnID           string `json:"conn_id"`
	Hops             []Hop  `json:"hops"`
}

// Clone returns a deep copy.
func (i Identity) Clone() Identity {
	cp := i
	if i.Hops != nil {
		cp.Hops = append([]Hop(nil), i.Hops...)
	}
	return cp
}

// PoolKey identifies the connection-pool bucket. It excludes ConnID: every
// connection for the same identity tuple shares a bucket, but every distinct
// identity gets its own bucket even when Target is identical.
func (i Identity) PoolKey() string {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%d|%s|%s|%s", i.Tenant, i.PolicyGeneration, i.OriginalName, i.ResolutionSource, i.Target)
	for _, hop := range i.Hops {
		fmt.Fprintf(h, "|hop:%s->%s@%s", hop.From, hop.To, hop.Address)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Fingerprint is the canonical full-identity hash, including ConnID. It is used
// in decision logs so two interleaved requests can never be confused.
func (i Identity) Fingerprint() string {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%d|%s|%s|%s|%s", i.Tenant, i.PolicyGeneration,
		i.OriginalName, i.ResolutionSource, i.Target, i.ConnID)
	for _, hop := range i.Hops {
		fmt.Fprintf(h, "|hop:%s->%s@%s", hop.From, hop.To, hop.Address)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Token is the authenticated credential sent on a mux stream.
type Token struct {
	Identity Identity `json:"identity"`
	Nonce    string   `json:"nonce"`
	MAC      string   `json:"mac"`
}

var errBadToken = errors.New("authz: invalid or tampered token")

// sign computes the HMAC-SHA256 over the canonical token body.
func sign(secret []byte, t *Token) string {
	body, _ := json.Marshal(struct {
		Identity Identity `json:"identity"`
		Nonce    string   `json:"nonce"`
	}{t.Identity, t.Nonce})
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// MintToken builds an HMAC-signed token for an identity.
func MintToken(secret []byte, id Identity, nonce string) Token {
	t := Token{Identity: id, Nonce: nonce}
	t.MAC = sign(secret, &t)
	return t
}

// VerifyToken checks the MAC and returns the authenticated identity.
func VerifyToken(secret []byte, raw []byte) (Identity, error) {
	var t Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return Identity{}, fmt.Errorf("%w: %v", errBadToken, err)
	}
	if t.Identity.ConnID == "" {
		return Identity{}, fmt.Errorf("%w: missing conn binding", errBadToken)
	}
	want := sign(secret, &t)
	if !hmac.Equal([]byte(want), []byte(t.MAC)) {
		return Identity{}, errBadToken
	}
	return t.Identity, nil
}
