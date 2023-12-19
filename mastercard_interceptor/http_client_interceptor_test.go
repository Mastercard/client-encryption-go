package mastercard_interceptor_test

import (
	"github.com/mastercard/client-encryption-go/field_level_encryption"
	"github.com/mastercard/client-encryption-go/mastercard_interceptor"
	"testing"
)

func TestHttpClientInterceptor(t *testing.T) {
	config := field_level_encryption.FieldLevelEncryptionConfig{}
	client, e := mastercard_interceptor.GetHttpClient(config, nil)
	if e != nil || client == nil {
		t.Errorf("Expected http.Client, but got %v", e)
	}
}
