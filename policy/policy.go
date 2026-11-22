// Package policy defines authorization policy snapshots, rule evaluation and
// permanent revocation tombstones.
//
// A snapshot is an immutable, generation-numbered set of rules. Publishing a
// snapshot in which a previously allowed permission disappears (rule removed or
// Allowed flipped to false) creates a tombstone. Tombstones outlive every later
// snapshot, including rollbacks: rolling policy back to an older generation that
// re-allows the same tenant/name does NOT restore the permission.
package policy

import (
	"strings"
	"time"

	"egressz/authz"
)

// Rule is one policy entry. The policy key is (Tenant, OriginalName).
type Rule struct {
	Tenant       string   `json:"tenant"`
	OriginalName string   `json:"original_name"`
	Allowed      bool     `json:"allowed"`
	MaxRedirects int      `json:"max_redirects"`
	DenyTargets  []string `json:"deny_targets"`
}

// Snapshot is an immutable policy generation.
type Snapshot struct {
	Generation int64  `json:"generation"`
	Rules      []Rule `json:"rules"`
}

// Tombstone records a revocation that can never be undone by policy rollback.
type Tombstone struct {
	Tenant       string    `json:"tenant"`
	OriginalName string    `json:"original_name"`
	Generation   int64     `json:"generation"`
	Reason       string    `json:"reason"`
	ObservedAt   time.Time `json:"observed_at"`
}

// Key returns the permission key the tombstone applies to.
func (t Tombstone) Key() string { return PermissionKey(t.Tenant, t.OriginalName) }

// PermissionKey is the canonical key for a permission.
func PermissionKey(tenant, originalName string) string {
	return tenant + "\x00" + originalName
}

func ruleIndex(rules []Rule) map[string]Rule {
	m := make(map[string]Rule, len(rules))
	for _, r := range rules {
		m[PermissionKey(r.Tenant, r.OriginalName)] = r
	}
	return m
}

// Lookup returns the rule for a permission in this snapshot.
func (s Snapshot) Lookup(tenant, originalName string) (Rule, bool) {
	r, ok := ruleIndex(s.Rules)[PermissionKey(tenant, originalName)]
	return r, ok
}

// Permits evaluates the rule against a concrete redirect chain.
func (r Rule) Permits(redirectHops int, hopAddresses []string) (bool, string) {
	if !r.Allowed {
		return false, "rule_denied"
	}
	if r.MaxRedirects >= 0 && redirectHops > r.MaxRedirects {
		return false, "redirect_chain_too_long"
	}
	for _, denied := range r.DenyTargets {
		for _, addr := range hopAddresses {
			if addr == denied {
				return false, "redirect_target_denied:" + denied
			}
		}
	}
	return true, ""
}

// Decision is the terminal verdict for an identity.
type Decision string

const (
	Allow Decision = "ALLOW"
	Deny  Decision = "DENY"
)

// Result is the outcome of evaluating one identity against a policy bundle.
type Result struct {
	Decision   Decision
	Reason     string
	Generation int64
}

// Bundle is the full authorization view a decision point holds: one snapshot
// plus every tombstone observed so far.
type Bundle struct {
	Snapshot   Snapshot
	Tombstones []Tombstone
	Version    int64 // monotonic watch version, independent of policy generation
}

// Evaluate makes a fail-closed decision. A nil/empty bundle denies everything:
// a decision point that has never received policy must not default to allow.
func Evaluate(b Bundle, id authz.Identity) Result {
	if b.Snapshot.Generation == 0 && len(b.Snapshot.Rules) == 0 {
		return Result{Decision: Deny, Reason: "no_policy_loaded", Generation: 0}
	}
	for _, t := range b.Tombstones {
		if t.Key() == PermissionKey(id.Tenant, id.OriginalName) {
			return Result{Decision: Deny, Reason: "revoked:" + t.Reason, Generation: b.Snapshot.Generation}
		}
	}
	rule, ok := b.Snapshot.Lookup(id.Tenant, id.OriginalName)
	if !ok {
		return Result{Decision: Deny, Reason: "no_matching_rule", Generation: b.Snapshot.Generation}
	}
	addrs := make([]string, 0, len(id.Hops))
	for _, h := range id.Hops {
		addrs = append(addrs, h.Address)
	}
	if ok, reason := rule.Permits(len(id.Hops), addrs); !ok {
		return Result{Decision: Deny, Reason: reason, Generation: b.Snapshot.Generation}
	}
	return Result{Decision: Allow, Reason: "", Generation: b.Snapshot.Generation}
}

// DiffRevoked returns permission keys that were allowed in old but are not
// allowed in new (removed rules or Allowed flipped to false).
func DiffRevoked(old, new Snapshot) []struct {
	Tenant, Name, Reason string
} {
	var out []struct {
		Tenant, Name, Reason string
	}
	oldIdx := ruleIndex(old.Rules)
	newIdx := ruleIndex(new.Rules)
	for key, oldRule := range oldIdx {
		if !oldRule.Allowed {
			continue
		}
		newRule, ok := newIdx[key]
		switch {
		case !ok:
			out = append(out, struct{ Tenant, Name, Reason string }{oldRule.Tenant, oldRule.OriginalName, "rule_removed"})
		case !newRule.Allowed:
			out = append(out, struct{ Tenant, Name, Reason string }{oldRule.Tenant, oldRule.OriginalName, "rule_set_deny"})
		}
	}
	return out
}

// ReasonIsRevocation reports whether a deny reason originated from a tombstone.
func ReasonIsRevocation(reason string) bool {
	return strings.HasPrefix(reason, "revoked:")
}
