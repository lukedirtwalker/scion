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

import "github.com/scionproto/scion/go/lib/scrypto/cert/v2"

// KeyChanges is a list of key types that changed.
type KeyChanges []cert.KeyType

// ExtractKeyChanges extracts the key changes in the request, that is trying to
// update the cert.
func ExtractKeyChanges(req ValidRequest) KeyChanges {
	var changes KeyChanges
	for keyType, meta := range req.Cert.Base.Keys {
		reqMeta := req.Req.Base.Keys[keyType]
		if reqMeta.KeyVersion != meta.KeyVersion {
			changes = append(changes, keyType)
		}
	}
	return changes
}

// POPValidator validates
type POPValidator struct {
	KeyChanges KeyChanges
	Request    ValidRequest
}
