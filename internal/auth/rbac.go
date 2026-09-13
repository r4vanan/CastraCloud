package auth

// Roles supported by the platform.
const (
	RoleOwner   = "owner"
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleViewer  = "viewer"
)

// Permissions follow the "resource:action" convention and are checked by the
// API's guard middleware.
const (
	PermFindingsRead    = "findings:read"
	PermFindingsWrite   = "findings:write"
	PermAssetsRead      = "assets:read"
	PermConnectorsRead  = "connectors:read"
	PermConnectorsWrite = "connectors:write"
	PermScansRun        = "scans:run"
	PermDomainsRead     = "domains:read"
	PermDomainsWrite    = "domains:write"
	PermWAFRead         = "waf:read"
	PermWAFWrite        = "waf:write"
	PermUsersManage     = "users:manage"
	PermAuditRead       = "audit:read"
	PermComplianceRead  = "compliance:read"
	PermAlertsRead      = "alerts:read"
	PermAlertsWrite     = "alerts:write"
)

func allPermissions() map[string]bool {
	return map[string]bool{
		PermFindingsRead:    true,
		PermFindingsWrite:   true,
		PermAssetsRead:      true,
		PermConnectorsRead:  true,
		PermConnectorsWrite: true,
		PermScansRun:        true,
		PermDomainsRead:     true,
		PermDomainsWrite:    true,
		PermWAFRead:         true,
		PermWAFWrite:        true,
		PermUsersManage:     true,
		PermAuditRead:       true,
		PermComplianceRead:  true,
		PermAlertsRead:      true,
		PermAlertsWrite:     true,
	}
}

var rolePermissions = map[string]map[string]bool{
	RoleOwner: allPermissions(),
	RoleAdmin: func() map[string]bool {
		m := allPermissions()
		delete(m, PermUsersManage)
		return m
	}(),
	RoleAnalyst: {
		PermFindingsRead:   true,
		PermFindingsWrite:  true,
		PermAssetsRead:     true,
		PermScansRun:       true,
		PermDomainsRead:    true,
		PermWAFRead:        true,
		PermComplianceRead: true,
		PermAlertsRead:     true,
	},
	RoleViewer: {
		PermFindingsRead:   true,
		PermAssetsRead:     true,
		PermDomainsRead:    true,
		PermWAFRead:        true,
		PermAuditRead:      true,
		PermComplianceRead: true,
		PermAlertsRead:     true,
	},
}

// HasPermission reports whether the role is allowed the given permission.
func HasPermission(role, perm string) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return perms[perm]
}

// IsValidRole reports whether the role name is a known platform role.
func IsValidRole(role string) bool {
	_, ok := rolePermissions[role]
	return ok
}
