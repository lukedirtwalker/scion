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

package renewal

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Errors that map to the errors in
// https://github.com/scionproto/scion/blob/master/doc/CertificateRenewal.md#supported-error-names
var (
	// ErrMalformed indicates the request is malformed.
	ErrMalformed = serrors.New("malformed request")
	// ErrInvalidSig indicates signature verification problems.
	ErrInvalidSig = serrors.New("invalid signature")
	// ErrNotCustomer indicates that a request was made for a non customer.
	ErrNotCustomer = serrors.New("not customer")
	// ErrExists indicates that the requested certificate version already
	// exists.
	ErrExists = serrors.New("certificate version exists")
	// ErrExpired indicates that the request is outdated.
	ErrExpired = serrors.New("request expired")
	// ErrPolicy indicates that the request violates the issuer's policy.
	ErrPolicy = serrors.New("policy violation")
)

// ValidationStore is the required stored information needed for validation.
type ValidationStore interface {
	// IsCustomer returns whether the given IA is in a customer relation with
	// this AS.
	IsCustomer(context.Context, addr.IA) (bool, error)
	// ActiveSignKey returns the public key identified by the ID. Return an
	// error if the key is not active or is not found in any active AS
	// certificate.
	ActiveSignKey(context.Context, keyconf.ID) ([]byte, error)
	// LatestChainVersion returns the latest chain version of the given IA.
	LatestChainVersion(context.Context, addr.IA) (scrypto.Version, error)
}

// Validator can be used to validate a request, this includes verifying the
// signatures and the proof of possessions.
type Validator struct {
	Store ValidationStore
}

// Validate validates a signed request.
func (v Validator) Validate(r SignedRequest) (ValidatedRequest, error) {
	return ValidatedRequest{}, serrors.New("NYI")
}

// ValidatedRequest is the validated request.
type ValidatedRequest cert.Base
