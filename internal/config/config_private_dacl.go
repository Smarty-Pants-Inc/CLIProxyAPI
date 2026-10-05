package config

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
