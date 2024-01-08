package utils

import "strings"

func IsNullOrEmpty(str string) bool {
	s := strings.ReplaceAll(str, " ", "")
	return s == ""
}
