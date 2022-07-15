package utils_test

import (
	"bytes"
	"testing"
	"testing/quick"

	"github.com/mastercard/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
)

func TestConcat(t *testing.T) {
	f := func(firstArray []byte, secondArray []byte) bool {
		res := utils.Concat(firstArray, secondArray)
		lenA := len(firstArray)
		lenB := len(secondArray)
		if len(res) != lenA+lenB {
			return false
		}
		if !bytes.Equal(res[:lenA], firstArray) {
			return false
		}
		if !bytes.Equal(res[lenA:], secondArray) {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestByteLength(t *testing.T) {
	f := func(bitLength int) bool {
		return utils.ByteLength(bitLength) == (bitLength / 8)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestSubArray(t *testing.T) {
	arr := []byte("abcdefghijk")
	assert.Equal(t, 3, len(utils.SubArray(arr, 3, 3)))
	assert.Equal(t, []byte("def"), utils.SubArray(arr, 3, 3))
}
