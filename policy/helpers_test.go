package policy

import "egressz/authz"

func testIdentity(tenant, name string) authz.Identity {
	return authz.Identity{Tenant: tenant, OriginalName: name}
}
