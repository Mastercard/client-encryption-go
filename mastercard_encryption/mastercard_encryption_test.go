package mastercard_encryption

import (
	"fmt"
	"github.com/mastercard/client-encryption-go/field_level_encryption"
	"github.com/mastercard/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptPayload(t *testing.T) {
	payload := `{
  "refId": "ecb2d942-eabd-42b6-87fd-69c19692bdc6",
  "timestamp": "2021-03-16T20:34:37-06:00",
  "icaNumber": "1076",
  "transactionIdentifiers": [
    {
      "cfcKey": "ARN",
      "cfcValue": "11111111200000000000000"
    },
    {
      "cfcKey": "BRN",
      "cfcValue": "543REF"
    }
  ],
  "cardNumber": "5587450000000008074",
  "acquirerId": "2742",
  "fraudTypeCode": "01",
  "fraudSubTypeCode": "U",
  "cardProductCode": "CIR",
  "transactionDate": "20200215",
  "settlementDate": "20200216",
  "fraudPostedDate": "20210316",
  "cardholderReportedDate": "20210314",
  "transactionAmount": "56823",
  "transactionCurrencyCode": "840",
  "billingAmount": "56823",
  "billingCurrencyCode": "840",
  "merchantId": "6698696",
  "merchantName": "BANKNEWPORT",
  "merchantCity": "Phoenix",
  "merchantStateProvinceCode": "AZ",
  "merchantCountryCode": "USA",
  "merchantPostalCode": "85001",
  "merchantCategoryCode": "6011",
  "terminalAttendanceIndicator": "0",
  "terminalId": "5055D305",
  "terminalOperatingEnvironment": "1",
  "cardholderPresenceIndicator": "0",
  "cardPresenceIndicator": "1",
  "cardInPossession": "Y",
  "catLevelIndicator": "2",
  "terminalCapabilityIndicator": "0",
  "posEntryMode": "00",
  "cvcInvalidIndicator": "M",
  "avsResponseCode": "U",
  "authResponseCode": "00",
  "secureCode": "9",
  "accountDeviceType": "A",
  "transactionIndicator": "M101",
  "memo": "This is a sample FDA complete request.",
  "issuerSCAExemption": "09"
}`

	certificatePath := "../testdata/certificates/fraudsubmissionapiClientEnc1689703308.pem"
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "03688777b9f0074fa6c97adc68488c5898cc8c117fdc74d2a668d70ae381a5d7"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig := cb.WithEncryptionCertificate(certificate).
		WithEncryptionPath("$", "$").
		WithOaepPaddingDigestAlgorithm("SHA-256").
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding("HEX").
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	fmt.Println(encryptedPayload)
}
