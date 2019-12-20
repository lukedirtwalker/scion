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

package reissuance_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/cert_srv/internal/reissuance"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestValidateRequest(t *testing.T) {

	tests := map[string]struct {
		Expect      func(*cert.AS, *reissuance.Request) reissuance.ValidRequest
		ExpectedErr error
	}{
		"Valid extension": {
			Expect: func(c *cert.AS, r *reissuance.Request) reissuance.ValidRequest {
				return reissuance.ValidRequest{Cert: *c, Req: *r}
			},
		},
		"Valid with key update": {
			Expect: func(c *cert.AS, r *reissuance.Request) reissuance.ValidRequest {
				// TODO add update
				return reissuance.ValidRequest{Cert: *c, Req: *r}
			},
		},
		"Invalid version jump": {
			Expect: func(c *cert.AS, r *reissuance.Request) reissuance.ValidRequest {
				r.Base.Version = c.Base.Version + 2
				return reissuance.ValidRequest{}
			},
			ExpectedErr: reissuance.ErrInvalidRequest,
		},
		"Invalid subject": {
			Expect: func(c *cert.AS, r *reissuance.Request) reissuance.ValidRequest {
				r.Base.Subject = xtest.MustParseIA("1-ff00:0:112")
				return reissuance.ValidRequest{}
			},
			ExpectedErr: reissuance.ErrInvalidRequest,
		},
		"Invalid validity": {
			Expect: func(c *cert.AS, r *reissuance.Request) reissuance.ValidRequest {
				r.Base.Validity.NotAfter.Time = time.Time{}
				return reissuance.ValidRequest{}
			},
			ExpectedErr: reissuance.ErrInvalidRequest,
		},
		"Missing key": {
			Expect: func(c *cert.AS, r *reissuance.Request) reissuance.ValidRequest {
				delete(r.Base.Keys, cert.SigningKey)
				return reissuance.ValidRequest{}
			},
			ExpectedErr: reissuance.ErrInvalidRequest,
		},
		"Missing pop": {
			Expect: func(c *cert.AS, r *reissuance.Request) reissuance.ValidRequest {
				r.Keys[cert.SigningKey] = scrypto.KeyMeta{
					KeyVersion: 2,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte("signKey2"),
				}
				return reissuance.ValidRequest{}
			},
			ExpectedErr: reissuance.ErrInvalidRequest,
		},
		"Invalid pop": {
			Expect: func(c *cert.AS, r *reissuance.Request) reissuance.ValidRequest {
				r.Keys[cert.SigningKey] = scrypto.KeyMeta{
					KeyVersion: 2,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte("signKey2"),
				}
				r.POPs = []reissuance.POP{{
					Encoded:          reissuance.EncodedBaseRequest("foo"),
					EncodedProtected: "bar",
					Signature:        []byte("c2lnbmF0dXJl")}}
				return reissuance.ValidRequest{}
			},
			ExpectedErr: reissuance.ErrInvalidRequest,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			c := newBaseCert(now)
			req := reissuance.Request{
				BaseRequest: newBaseRequest(now),
			}
			expected := test.Expect(&c, &req)
			vr, err := reissuance.ValidateRequest(c, req)
			xtest.AssertErrorsIs(t, err, test.ExpectedErr)
			assert.Equal(t, expected, vr)
		})
	}
}

func newBaseCert(now time.Time) cert.AS {
	now = now.Truncate(time.Second)
	return cert.AS{
		Base: cert.Base{
			Subject:       xtest.MustParseIA("1-ff00:0:111"),
			Version:       1,
			FormatVersion: 1,
			Description:   "Base cert description",
			Validity: &scrypto.Validity{
				NotBefore: util.UnixTime{Time: now.Add(-8759 * time.Hour)},
				NotAfter:  util.UnixTime{Time: now.Add(time.Hour)},
			},
			Keys: map[cert.KeyType]scrypto.KeyMeta{
				cert.EncryptionKey: {
					KeyVersion: 1,
					Algorithm:  scrypto.Curve25519xSalsa20Poly1305,
					Key:        []byte("encryptKey1"),
				},
				cert.RevocationKey: {
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte("revKey1"),
				},
				cert.SigningKey: {
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte("signKey1"),
				},
			},
		},
	}
}
