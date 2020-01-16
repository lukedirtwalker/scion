// Copyright 2019 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package renewal_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/renewal"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestParseSignedRequest(t *testing.T) {
	tests := map[string]struct {
		Input          string
		SignedRequest  renewal.SignedRequest
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"payload": "testrequest",
				"protected": "protected",
				"signature": "c2lnbmF0dXJl"
			}
			`,
			SignedRequest: renewal.SignedRequest{
				Encoded:          "testrequest",
				EncodedProtected: "protected",
				Signature:        []byte("signature"),
			},
		},
		"Invalid JSON": {
			Input: `
			{
				"payload": "testrequest",
				"protected": "protected",
				"signature": "not base64"
			}
			`,
			ExpectedErrMsg: "illegal base64 data at input byte 3",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			sr, err := renewal.ParseSignedRequest([]byte(test.Input))
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, test.SignedRequest, sr)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestProtectedUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		Protected      renewal.Protected
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
				"key_version": 2,
				"crit": ["key_type", "key_version"]
			}`,
			Protected: renewal.Protected{
				Algorithm:  scrypto.Ed25519,
				KeyType:    renewal.SigningKey,
				KeyVersion: 2,
			},
		},
		"Algorithm not set": {
			Input: `
			{
				"key_type": "signing",
				"key_version": 2,
				"crit": ["key_type", "key_version"]
			}`,
			ExpectedErrMsg: renewal.ErrMissingProtectedField.Error(),
		},
		"Key type not set": {
			Input: `
			{
				"alg": "ed25519",
				"key_version": 2,
				"crit": ["key_type", "key_version"]
			}`,
			ExpectedErrMsg: renewal.ErrMissingProtectedField.Error(),
		},
		"Key version not set": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
				"crit": ["key_type", "key_version"]
			}`,
			ExpectedErrMsg: renewal.ErrMissingProtectedField.Error(),
		},
		"crit not set": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
				"key_version": 2
			}`,
			ExpectedErrMsg: renewal.ErrMissingProtectedField.Error(),
		},
		"unknown field": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
				"version": 2,
				"crit": ["key_type", "key_version"]
			}`,
			ExpectedErrMsg: `json: unknown field "version"`,
		},
		"invalid JSON": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
			`,
			ExpectedErrMsg: "unexpected end of JSON input",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var protected renewal.Protected
			err := json.Unmarshal([]byte(test.Input), &protected)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, test.Protected, protected)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestRequestInfoJSONConversion(t *testing.T) {
	signKey, err := scrypto.Base64.DecodeString("WmTLs8BiEdyLVOSLQR2Oopmt0Wz3ZtFd0v8FKCEB14M")
	require.NoError(t, err)
	revKey, err := scrypto.Base64.DecodeString("RUHOtezvoir6DWVCBBZjf3M_4giLbWgE0o3f4oJQu18")
	require.NoError(t, err)

	tests := map[string]struct {
		Input  string
		Modify func(r *renewal.RequestInfo)
	}{
		// input from the renewal document.
		"With revocation key": {
			Input: `
{
	"subject": "1-ff00:0:120",
	"version": 2,
	"format_version": 1,
	"description": "Certificate request",
	"validity": {
		"not_before": 1480927723,
		"not_after": 1512463723
	},
	"keys": {
		"signing": {
			"key": "WmTLs8BiEdyLVOSLQR2Oopmt0Wz3ZtFd0v8FKCEB14M"
		},
		"revocation": {
			"key": "RUHOtezvoir6DWVCBBZjf3M_4giLbWgE0o3f4oJQu18"
		}
	},
	"issuer": "1-ff00:0:130",
	"request_time": 1480927000
}`,
			Modify: func(r *renewal.RequestInfo) {},
		},
		"Without revocation key": {
			Input: `
{
	"subject": "1-ff00:0:120",
	"version": 2,
	"format_version": 1,
	"description": "Certificate request",
	"validity": {
		"not_before": 1480927723,
		"not_after": 1512463723
	},
	"keys": {
		"signing": {
			"key": "WmTLs8BiEdyLVOSLQR2Oopmt0Wz3ZtFd0v8FKCEB14M"
		}
	},
	"issuer": "1-ff00:0:130",
	"request_time": 1480927000
}`,
			Modify: func(r *renewal.RequestInfo) {
				r.Keys.Revocation = nil
			},
		},
		"With optional distribution points": {
			Input: `
{
	"subject": "1-ff00:0:120",
	"version": 2,
	"format_version": 1,
	"description": "Certificate request",
	"optional_distribution_points": [
		"1-ff00:0:140"
	],
	"validity": {
		"not_before": 1480927723,
		"not_after": 1512463723
	},
	"keys": {
		"signing": {
			"key": "WmTLs8BiEdyLVOSLQR2Oopmt0Wz3ZtFd0v8FKCEB14M"
		},
		"revocation": {
			"key": "RUHOtezvoir6DWVCBBZjf3M_4giLbWgE0o3f4oJQu18"
		}
	},
	"issuer": "1-ff00:0:130",
	"request_time": 1480927000
}`,
			Modify: func(r *renewal.RequestInfo) {
				r.OptionalDistributionPoints = append(r.OptionalDistributionPoints,
					xtest.MustParseIA("1-ff00:0:140"))
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			expected := createSpecRequestInfo(signKey, revKey)
			var reqInfo renewal.RequestInfo
			err = json.Unmarshal([]byte(test.Input), &reqInfo)
			require.NoError(t, err)
			test.Modify(&expected)
			assert.Equal(t, expected, reqInfo)
			raw, err := json.MarshalIndent(expected, "", "\t")
			require.NoError(t, err)
			assert.Equal(t, strings.TrimSpace(test.Input), string(raw))
		})
	}
}

func createSpecRequestInfo(signKey, revKey []byte) renewal.RequestInfo {
	return renewal.RequestInfo{
		Subject:       xtest.MustParseIA("1-ff00:0:120"),
		Version:       2,
		FormatVersion: 1,
		Description:   "Certificate request",
		Validity: &scrypto.Validity{
			NotBefore: util.UnixTime{Time: time.Unix(1480927723, 0)},
			NotAfter:  util.UnixTime{Time: time.Unix(1512463723, 0)},
		},
		Keys: renewal.Keys{
			Signing:    renewal.KeyMeta{Key: signKey},
			Revocation: &renewal.KeyMeta{Key: revKey},
		},
		Issuer:      xtest.MustParseIA("1-ff00:0:130"),
		RequestTime: util.UnixTime{Time: time.Unix(1480927000, 0)},
	}
}

func createSpecSignatureMetadata() renewal.Protected {
	return renewal.Protected{
		Algorithm:  scrypto.Ed25519,
		KeyType:    renewal.SigningKey,
		KeyVersion: 21,
	}
}

func createSpecSignatureMetadata() renewal.Protected {
	return renewal.Protected{
		Algorithm:  scrypto.Ed25519,
		KeyType:    renewal.RevocationKey,
		KeyVersion: 29,
	}
}
