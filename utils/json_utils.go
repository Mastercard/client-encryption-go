package utils

import "strings"

func RemoveRoot(json string) string {
	if json[0] == '$' && json != "$" {
		return json[2:]
	}
	return json
}

func GetParent(path string) string {
	keys := strings.Split(path, ".")
	parent := keys[:len(keys)-1]
	return strings.Join(parent, ".")
}
