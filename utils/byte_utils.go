package utils

import (
	"encoding/json"
	"io"
)

func ParseReader(r io.Reader) string {
	var m map[string]interface{}
	_ = json.NewDecoder(r).Decode(&m)
	b, _ := json.MarshalIndent(m, "", "  ")
	return string(b)
}

func Concat(array1, array2 []byte) []byte {
	return append(array1, array2...)
}

func ByteLength(bitLength int) int {
	return bitLength / 8
}

func SubArray(byteArray []byte, beginIndex, length int) []byte {
	return byteArray[beginIndex : beginIndex+length]
}
