package config

// Ownership carries implicit DACL-control rights. It is part of the private-file
// boundary, independently of the exact protected DACL projection. Windows API
// failures must be rejected by the caller before providing these projections.
func privateConfigOwnerAndDACLMatches(control uint16, nonNull bool, owner, user, projected, expected string) bool {
	return user != "" && owner == user &&
		privateConfigDACLMatches(control, nonNull, projected, expected)
}

// Windows can add descriptor bookkeeping (for example DACL_AUTO_INHERITED)
// without changing the access policy. Check the required control bits separately
// from a DACL-only projection. The projection retains every ACE and ACE flag;
// equality with the current-user template therefore does not admit other grants.
func privateConfigDACLMatches(control uint16, nonNull bool, projected, expected string) bool {
	const daclPresent = 0x0004
	const daclProtected = 0x1000
	return control&(daclPresent|daclProtected) == daclPresent|daclProtected &&
		nonNull && expected != "" && projected == expected
}
