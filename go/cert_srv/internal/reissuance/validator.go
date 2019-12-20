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

package reissuance

import (
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ErrInvalidRequest indicates an invalid request.
var ErrInvalidRequest = serrors.New("invalid request")

// ValidRequest represents a validated request that requests and update of the
// cert.
type ValidRequest struct {
	Cert cert.AS
	Req  Request
}

func ValidateRequest(asCert cert.AS, req Request) (ValidRequest, error) {
	return ValidRequest{}, serrors.New("NYI")
}
