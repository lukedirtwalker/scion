// Copyright 2020 Anapaya Systems
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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/cert/renewal"
	"github.com/scionproto/scion/go/lib/scrypto/cert/renewal/mock_renewal"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Key struct {
	Priv    []byte
	Public  []byte
	Alg     string
	Version scrypto.KeyVersion
	Type    renewal.KeyType
}

func genKey(t *testing.T, v scrypto.KeyVersion, kt renewal.KeyType) Key {
	public, private, err := scrypto.GenKeyPair(scrypto.Ed25519)
	require.NoError(t, err)
	return Key{
		Priv:    private,
		Public:  public,
		Alg:     scrypto.Ed25519,
		Version: v,
		Type:    kt,
	}
}

type Keys struct {
	CurrentSign   Key
	NewSign       Key
	NewRevocation Key
}

func genKeys(t *testing.T) Keys {
	return Keys{
		CurrentSign:   genKey(t, 1, renewal.SigningKey),
		NewSign:       genKey(t, 2, renewal.SigningKey),
		NewRevocation: genKey(t, 1, renewal.RevocationKey),
	}
}

func TestValidatorValidate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := mock_renewal.NewMockValidationStore(ctrl)
		keys := genKeys(t)
		req := createRequest(t, keys, RequestModifiers{})
		validator := renewal.Validator{Store: store}

		validated, err := validator.Validate(req)
		xtest.AssertErrorsIs(t, err, nil)
		assert.Equal(t, expectedValidated(t, req), validated)
	})

	// validation violations
	t.Run("missing signing key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := mock_renewal.NewMockValidationStore(ctrl)
		keys := genKeys(t)
		req := createRequest(t, keys, RequestModifiers{
			RequestInfo: func(r *renewal.RequestInfo) {
				r.Keys.Signing = renewal.KeyMeta{}
			},
		})
		validator := renewal.Validator{Store: store}

		validated, err := validator.Validate(req)
		xtest.AssertErrorsIs(t, err, nil)
		assert.Equal(t, expectedValidated(t, req), validated)
	})
	// missing POP for signing key
	// revocation key present without POP
	// validity period too long
	// validity in the future

	// TODO can we check invalid integers, invalid field in metadata?

	// default policy violations
	t.Run("outdated request", func(t *testing.T) {

	})
	t.Run("inactive sign key used", func(t *testing.T) {

	})
	t.Run("not a customer", func(t *testing.T) {

	})
	t.Run("invalid version increment", func(t *testing.T) {

	})

	// signature issues
	// main signature wrong
	// POP signing key wrong
	// POP revocation key wrong

}

func expectedValidated(t *testing.T, r renewal.SignedRequest) renewal.ValidatedRequest {
	req, err := r.Encoded.Decode()
	require.NoError(t, err)
	reqI, err := req.Encoded.Decode()
	require.NoError(t, err)
	keys := make(map[cert.KeyType]scrypto.KeyMeta)
	for _, pop := range req.POPs {
		p, err := pop.Protected.Decode()
		require.NoError(t, err)
		switch p.KeyType {
		case renewal.SigningKey:
			keys[cert.SigningKey] = scrypto.KeyMeta{
				KeyVersion: p.KeyVersion,
				Algorithm:  p.Algorithm,
				Key:        []byte(reqI.Keys.Signing.Key),
			}
		case renewal.RevocationKey:
			keys[cert.RevocationKey] = scrypto.KeyMeta{
				KeyVersion: p.KeyVersion,
				Algorithm:  p.Algorithm,
				Key:        []byte(reqI.Keys.Signing.Key),
			}
		default:
			require.Fail(t, "invalid key type: %s", p.KeyType)
		}
	}
	v := renewal.ValidatedRequest{
		Subject:                    reqI.Subject,
		Version:                    reqI.Version,
		FormatVersion:              reqI.FormatVersion,
		Description:                reqI.Description,
		OptionalDistributionPoints: reqI.OptionalDistributionPoints,
		Validity:                   reqI.Validity,
		Keys:                       keys,
	}
	return v
}

type RequestModifiers struct {
	RequestInfo   func(r *renewal.RequestInfo)
	Request       func(r *renewal.Request)
	SignedRequest func(r *renewal.SignedRequest)
}

func (m RequestModifiers) ModifyRI(r *renewal.RequestInfo) {
	if m.RequestInfo != nil {
		m.RequestInfo(r)
	}
}

func (m RequestModifiers) ModifyR(r *renewal.Request) {
	if m.Request != nil {
		m.Request(r)
	}
}

func (m RequestModifiers) ModifySR(r *renewal.SignedRequest) {
	if m.SignedRequest != nil {
		m.SignedRequest(r)
	}
}

func createRequest(t *testing.T, keys Keys, m RequestModifiers) renewal.SignedRequest {
	reqInfo := newRequestInfo(time.Now())
	reqInfo.Keys.Signing.Key = keys.NewSign.Public
	reqInfo.Keys.Revocation.Key = keys.NewRevocation.Public
	m.ModifyRI(&reqInfo)

	erqi, err := renewal.EncodeRequestInfo(&reqInfo)
	require.NoError(t, err)
	req := renewal.Request{
		Encoded: erqi,
	}
	req.POPs = append(req.POPs, signPOP(t, keys.NewSign, erqi))
	if keys.NewRevocation.Priv != nil {
		req.POPs = append(req.POPs, signPOP(t, keys.NewRevocation, erqi))
	}
	m.ModifyR(&req)
	ereq, err := renewal.EncodeRequest(&req)
	require.NoError(t, err)
	sr := renewal.SignedRequest{
		Encoded:          ereq,
		EncodedProtected: encodedProtectedForKey(t, keys.CurrentSign),
	}
	sr.Signature, err = scrypto.Sign(sr.SigInput(), keys.CurrentSign.Priv, keys.CurrentSign.Alg)
	require.NoError(t, err)
	m.ModifySR(&sr)
	return sr
}

func signPOP(t *testing.T, key Key, erqi renewal.EncodedRequestInfo) renewal.POP {
	ep := encodedProtectedForKey(t, key)
	pop := renewal.POP{
		Protected: ep,
	}
	sig, err := scrypto.Sign(pop.SigInput(erqi), key.Priv, key.Alg)
	require.NoError(t, err)
	pop.Signature = sig
	return pop
}

func encodedProtectedForKey(t *testing.T, key Key) renewal.EncodedProtected {
	p := renewal.Protected{
		Algorithm:  key.Alg,
		KeyType:    key.Type,
		KeyVersion: key.Version,
	}
	ep, err := renewal.EncodeProtected(p)
	require.NoError(t, err)
	return ep
}

func removePOP(t *testing.T, r *renewal.Request, keyType renewal.KeyType) {
	pops := r.POPs[:0]
	for _, pop := range r.POPs {
		p, err := pop.Protected.Decode()
		require.NoError(t, err)
		if p.KeyType != keyType {
			pops = append(pops, pop)
		}
	}
	r.POPs = pops
}
