package osvdev

import "strings"

func isAllowedAlias(alias string) bool {
	if alias == "" {
		return false
	}
	allowedList := []string{aliasPrefixGO, aliasPrefixCVE, aliasPrefixOSV, aliasPrefixGHSA}
	for _, prefix := range allowedList {
		if strings.HasPrefix(alias, prefix) {
			return true
		}
	}
	return false
}
