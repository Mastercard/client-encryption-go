package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRemoveRoot_ShouldRemoveRootIfPresent(t *testing.T) {
	path := "$.path.to.foo"
	updatedPath := RemoveRoot(path)
	assert.Equal(t, "path.to.foo", updatedPath)
}

func TestRemoveRoot_ShouldNotRemoveRootIfItIsARootPath(t *testing.T) {
	path := "$"
	updatedPath := RemoveRoot(path)
	assert.Equal(t, "$", updatedPath)
}

func TestGetParent(t *testing.T) {
	path := "$.path.to.foo"
	parent := GetParent(path)
	assert.Equal(t, "$.path.to", parent)
}
