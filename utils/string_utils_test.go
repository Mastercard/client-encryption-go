package utils_test

import (
	"testing"

	"github.com/mastercard/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
)

func TestIsNullOrEmptyShouldReturnTrueForEmptyStrings(t *testing.T) {
	emptyString := ""
	result := utils.IsNullOrEmpty(emptyString)
	assert.True(t, result)
}

func TestIsNullOrEmptyShouldReturnFalseForPopulatedStrings(t *testing.T) {
	emptyString := "Test"
	result := utils.IsNullOrEmpty(emptyString)
	assert.False(t, result)
}
