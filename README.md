# client-encryption-go
[![](https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg)](https://developer.mastercard.com/)

## Table of Contents
- [Overview](#overview)
    * [Compatibility](#compatibility)
    * [References](#references)
- [Usage](#library-usage)
    * [Prerequisites](#prerequisites)
    * [Installation](#installation)
    * [Loading the Encryption Certificate](#loading-the-encryption-certificate)
    * [Loading the Decryption Key](#loading-the-decryption-key)
    * [Performing Payload Encryption and Decryption](#performing-payload-encryption-and-decryption)
    * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>
Library for Mastercard API compliant payload encryption/decryption.

### Compatibility <a name="compatibility"></a>
Go 1.15+

### References <a name="references"></a>
* [Securing Sensitive Data Using Payload Encryption](https://developer.mastercard.com/platform/documentation/security-and-authentication/securing-sensitive-data-using-payload-encryption/)

## Usage <a name="library-usage"></a>

### Prerequisites <a name="prerequisites"></a>
Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com).

As part of this set up, you'll receive:
* A public request encryption certificate (aka _Client Encryption Keys_)
* A private response decryption key (aka _Mastercard Encryption Keys_)

### Installation <a name="installation"></a>

####
```go
import github.com/mastercard/client-encryption-go
```

### Loading the Encryption Certificate <a name="loading-the-encryption-certificate"></a>
A `Certificate` can be created by calling the `utils.LoadSigningKey` function:
```go
import "github.com/mastercard/client-encryption-go/utils"

//…
encryptionCertificate, err := utils.LoadEncryptionCertificate("<insert certificate file path>")
//…
```

Supported certificate formats: PEM, DER.

### Loading the Decryption Key <a name="loading-the-decryption-key"></a>

#### From a PKCS#12 Key Store

A `PrivateKey` can be created from a PKCS#12 key store by calling `utils.LoadDecryptionKey` the following way:
```go
import "github.com/mastercard/client-encryption-go/utils"

//…
decryptionKey, err := utils.LoadDecryptionKey(
	"<insert PKCS#12 key file path>",
    "<insert key password>")
//…
```

#### From an Unencrypted Key File

A `PrivateKey` can be created from an unencrypted key file by calling `utils.LoadUnencryptedDecryptionKey` the following way:
```go
import "github.com/mastercard/client-encryption-go/utils"

//…
decryptionKey, err := utils.LoadUnencryptedDecryptionKey("<insert key file path>")
//…
```

Supported RSA key formats:
* PKCS#1 PEM (starts with "-----BEGIN RSA PRIVATE KEY-----")
* PKCS#8 PEM (starts with "-----BEGIN PRIVATE KEY-----")
* Binary DER-encoded PKCS#8

### Performing Payload Encryption and Decryption <a name="performing-payload-encryption-and-decryption"></a>

This library supports two types of encryption/decryption, both of which support field level and entire payload encryption: JWE encryption and what the library refers to as Field Level Encryption (Mastercard encryption), a scheme used by many services hosted on Mastercard Developers before the library added support for JWE.

+ [JWE Encryption and Decryption](#jwe-encryption-and-decryption)
+ [Mastercard Encryption and Decryption](#mastercard-encryption-and-decryption)

#### JWE Encryption and Decryption <a name="jwe-encryption-and-decryption"></a>

+ [Introduction](#jwe-introduction)
+ [Configuring the JWE Encryption](#configuring-the-jwe-encryption)
+ [Performing JWE Encryption](#performing-jwe-encryption)
+ [Performing JWE Decryption](#performing-jwe-decryption)
+ [Encrypting Entire Payloads](#encrypting-entire-payloads-jwe)
+ [Decrypting Entire Payloads](#decrypting-entire-payloads-jwe)

##### Introduction <a name="jwe-introduction"></a>

This library uses [JWE compact serialization](https://datatracker.ietf.org/doc/html/rfc7516#section-7.1) for the encryption of sensitive data.
The core methods responsible for payload encryption and decryption are `EncryptPayload` and `DecryptPayload` in the `encryption` package.

* `encryptPayload` usage:
```go
import "github.com/mastercard/client-encryption-go/encryption"
// …

encryptedPayload := encryption.EncryptPayload(payload, *config)
```

* `decryptPayload` usage:
```go
import "github.com/mastercard/client-encryption-go/encryption"
// …

decryptedPayload := encryption.DecryptPayload(payload, *config)
```

#### • Configuring the JWE Encryption <a name="configuring-the-jwe-encryption"></a>

Use the `JWEConfigBuilder` to create `JWEConfig` instances. Example:
```go
import "github.com/mastercard/client-encryption-go/jwe"
// …

cb := jwe.NewJWEConfigBuilder()
config := cb.WithDecryptionKey(decryptionKey).
    WithCertificate(encryptionCertificate).
    WithEncryptionPath("$.path.to.foo", "$.path.to.encryptedFoo").
    WithDecryptionPath("$.path.to.encryptedFoo.encryptedData", "$.path.to.foo").
    WithEncryptedValueFieldName("encryptedData").
    Build()
```

#### • Performing JWE Encryption <a name="performing-jwe-encryption"></a>

Call `encryption.EncryptPayload` with a JSON request payload and a `JWEConfig` instance.

Example using the configuration [above](#configuring-the-jwe-encryption):
```go
//…
payload := "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"foo\": {" +
    "                \"sensitiveField1\": \"sensitiveValue1\"," +
    "                \"sensitiveField2\": \"sensitiveValue2\"" +
    "            }" +
    "        }" +
    "    }" +
    "}"
encryptedPayload := encryption.EncryptPayload(payload, config)
//…
```

Output:
```json
{
    "path": {
        "to": {
            "encryptedFoo": {
                "encryptedData": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"
            }
        }
    }
}
```

#### • Performing JWE Decryption <a name="performing-jwe-decryption"></a>

Call `encryption.DecryptPayload` with a JSON response payload and a `JWEConfig` instance.

Example using the configuration [above](#configuring-the-jwe-encryption):
```go
encryptedPayload := "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"encryptedFoo\": {" +
    "                \"encryptedData\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"" +
    "            }" +
    "        }" +
    "    }" +
    "}"
decryptedPayload := encryption.DecryptPayload(payload, config)
```

Output:
```json
{
    "path": {
        "to": {
            "foo": {
                "sensitiveField1": "sensitiveValue1",
                "sensitiveField2": "sensitiveValue2"
            }
        }
    }
}
```

#### • Encrypting Entire Payloads <a name="encrypting-entire-payloads-jwe"></a>

Entire payloads can be encrypted using the "$" operator as encryption path:

```go
import "github.com/mastercard/client-encryption-go/jwe"
// …

cb := jwe.NewJWEConfigBuilder()
config := cb.WithCertificate(encryptionCertificate).
    WithEncryptionPath("$", "$").
    // …
    Build()
```

Example:
```go
payload := "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}"
encryptedPayload := encryption.EncryptPayload(payload, config)
```

Output:
```json
{
    "encryptedData": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"
}
```

#### • Decrypting Entire Payloads <a name="decrypting-entire-payloads-jwe"></a>

Entire payloads can be decrypted using the "$" operator as decryption path:

```go
import "github.com/mastercard/client-encryption-go/jwe"
// …

cb := jwe.NewJWEConfigBuilder()
config := cb.WithDecryptionKey(decryptionKey).
    WithDecryptionPath("$", "$").
    // …
    Build()
```

Example:
```go
encryptedPayload := "{" +
    "  \"encryptedData\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"" +
    "}"
payload = encryption.decryptPayload(encryptedPayload, config)
```

Output:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}
```

#### Mastercard Encryption and Decryption <a name="mastercard-encryption-and-decryption"></a>

+ [Introduction](#mastercard-introduction)
+ [Configuring the Mastercard Encryption](#configuring-the-mastercard-encryption)
+ [Performing Mastercard Encryption](#performing-mastercard-encryption)
+ [Performing Mastercard Decryption](#performing-mastercard-decryption)

##### Introduction <a name="mastercard-introduction"></a>

The core methods responsible for payload encryption and decryption are `EncryptPayload` and `DecryptPayload` in the `mastercard_encryption` package.

* `encryptPayload` usage:
```go
import "github.com/mastercard/client-encryption-go/mastercard_encryption"
// …

encryptedPayload := encryption.EncryptPayload(payload, *config)
```

* `decryptPayload` usage:
```go
import "github.com/mastercard/client-encryption-go/mastercard_encryption"
// …

decryptedPayload := encryption.DecryptPayload(payload, *config)
```

#### • Configuring the Mastercard Encryption <a name="#configuring-the-mastercard-encryption"></a>

Use the `FieldLevelEncryptionConfigBuilder` to create `FieldLevelEncryptionConfig` instances. Example:
```go
import "github.com/mastercard/client-encryption-go/field_level_encryption"
// …

cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
config, err := cb.WithDecryptionKey(decryptionKey).
    WithCertificate(encryptionCertificate).
    WithEncryptionPath("$.path.to.foo", "$.path.to.encryptedFoo").
    WithDecryptionPath("$.path.to.encryptedFoo.encryptedData", "$.path.to.foo").
    WithEncryptedValueFieldName("encryptedData").
    WithEncryptedKeyFieldName("encryptedKey").
    WithIvFieldName("iv").
    WithFieldValueEncoding(field_level_encryption.HEX).
    WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA256).
    Build()
```

##### Performing Mastercard Encryption <a name="performing-mastercard-encryption"></a>

Call `mastercard_encryption.EncryptPayload` with a JSON request payload and a `FieldLevelEncryptionConfig` instance.

Example using the configuration [above](#configuring-the-mastercard-encryption):
```go
//…
payload := "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"foo\": {" +
    "                \"sensitiveField1\": \"sensitiveValue1\"," +
    "                \"sensitiveField2\": \"sensitiveValue2\"" +
    "            }" +
    "        }" +
    "    }" +
    "}"
encryptedPayload := mastercard_encryption.EncryptPayload(payload, config)
//…
```

Output:
```json
{
  "path": {
    "to": {
      "encryptedFoo": {
        "iv": "7f1105fb0c684864a189fb3709ce3d28",
        "encryptedKey": "67f467d1b653d98411a0c6d3c…ffd4c09dd42f713a51bff2b48f937c8",
        "encryptedData": "b73aabd267517fc09ed72455c2…dffb5fa04bf6e6ce9ade1ff514ed6141",
        "publicKeyFingerprint": "80810fc13a8319fcf0e2e…82cc3ce671176343cfe8160c2279",
        "oaepHashingAlgorithm": "SHA256"
      }
    }
  }
}
```

##### Performing Mastercard Decryption <a name="performing-mastercard-decryption"></a>

Call `mastercard_encryption.DecryptPayload` with a JSON response payload and a `FieldLevelEncryptionConfig` instance.

Example using the configuration [above](#configuring-the-mastercard-encryption):
```go
response := "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"encryptedFoo\": {" +
    "               \"iv\": \"e5d313c056c411170bf07ac82ede78c9\"," +
	"               \"encryptedKey": "e3a56746c0f9109d18b3a2652b76…f16d8afeff36b2479652f5c24ae7bd\"," +
    "               \"encryptedData\": \"809a09d78257af5379df0c454dcdf…353ed59fe72fd4a7735c69da4080e74f\"," +
    "               \"oaepHashingAlgorithm\": \"SHA256\"," +
    "               \"publicKeyFingerprint\": \"80810fc13a8319fcf0e2e…3ce671176343cfe8160c2279\"" +
    "            }" +
    "        }" +
    "    }" +
    "}"
decryptedPayload := encryption.DecryptPayload(response, config)
```

Output:
```json
{
    "path": {
        "to": {
            "foo": {
                "sensitiveField1": "sensitiveValue1",
                "sensitiveField2": "sensitiveValue2"
            }
        }
    }
}
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification).
It provides generators and library templates for supporting multiple languages and frameworks.

The `interceptor` package will provide you with an interceptor you can use when configuring your API client.
This interceptor will take care of encrypting request and decrypting response payloads.

#### OpenAPI Generator
Client libraries can be generated using the following command:

```openapi-generator-cli generate -i openapi-spec.yaml -g go -o out```

See also:
* [OpenAPI Generator CLI Installation](https://openapi-generator.tech/docs/installation)
* [Config Options for go](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/go.md)

#### Usage
The interceptor package supports 2 types of encryption. 
1. Encryption with OAuth1.0a authentication
2. Encryption without authentication

#### Encryption with OAuth1.0a Authentication
Requests can be encrypted, with OAuth authentication as follows:

```go
import (
    oauth "github.com/mastercard/oauth1-signer-go"
    "github.com/mastercard/client-encryption-go/interceptor"
)

cb := jwe.NewJWEConfigBuilder()
jweConfig := cb.WithDecryptionKey(decryptionKey).
    WithCertificate(encryptionCertificate).
    WithEncryptionPath("$", "$").
	// …
	Build()

configuration := openapi.NewConfiguration()

// Signer from the oauth-signer-go library used for OAuth1.0a
signer := oauth.Signer{ConsumerKey: "<consumer-key>", SigningKey: "<signer-key>"}
encryptionClient, _ := interceptor.GetHttpClient(*jweConfig, signer.Sign)
configuration.HTTPClient = encryptionClient
apiClient := openapi.NewAPIClient(configuration)

serviceApi := apiClient.ServiceApi
// …
```

See also:
* [Mastercard OAuth Signer Library](https://github.com/Mastercard/oauth1-signer-go)
