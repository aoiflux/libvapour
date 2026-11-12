package tokensids

import "fmt"

// Microsoft Learn, TOKEN_GROUPS (winnt.h). SE_GROUP_LOGON_ID is two bits and
// is named only when both are set.
var groupAttributes = []struct {
	mask uint32
	name string
}{
	{0x00000001, "SE_GROUP_MANDATORY"},
	{0x00000002, "SE_GROUP_ENABLED_BY_DEFAULT"},
	{0x00000004, "SE_GROUP_ENABLED"},
	{0x00000008, "SE_GROUP_OWNER"},
	{0x00000010, "SE_GROUP_USE_FOR_DENY_ONLY"},
	{0x00000020, "SE_GROUP_INTEGRITY"},
	{0x00000040, "SE_GROUP_INTEGRITY_ENABLED"},
	{0x20000000, "SE_GROUP_RESOURCE"},
	{0xC0000000, "SE_GROUP_LOGON_ID"},
}

func attributeNames(attributes uint32) []string {
	var names []string
	rest := attributes
	for _, a := range groupAttributes {
		if attributes&a.mask == a.mask {
			names = append(names, a.name)
			rest &^= a.mask
		}
	}
	if rest != 0 {
		names = append(names, fmt.Sprintf("0x%x", rest))
	}
	return names
}
