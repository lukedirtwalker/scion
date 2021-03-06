// Copyright 2021 Anapaya Systems
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

package launcher_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/app/launcher"
)

func TestWaitForNetworkReady(t *testing.T) {
	testCases := map[string]struct {
		IPs       []net.IP
		Setup     func(t *testing.T) (context.Context, func())
		AssertErr assert.ErrorAssertionFunc
	}{
		"no IPs": {
			IPs: nil,
			Setup: func(_ *testing.T) (context.Context, func()) {
				return context.Background(), func() {}
			},
			AssertErr: assert.NoError,
		},
		"IPs not found time out": {
			IPs: []net.IP{net.ParseIP("192.0.2.42")},
			Setup: func(_ *testing.T) (context.Context, func()) {
				ctx, cancelF := context.WithTimeout(context.Background(), time.Millisecond*200)
				return ctx, cancelF
			},
			AssertErr: assert.Error,
		},
		"localhost": {
			IPs: []net.IP{net.ParseIP("127.0.0.1")},
			Setup: func(_ *testing.T) (context.Context, func()) {
				ctx, cancelF := context.WithTimeout(context.Background(), time.Millisecond*500)
				return ctx, cancelF
			},
			AssertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx, cleanup := tc.Setup(t)
			defer cleanup()
			tc.AssertErr(t, launcher.WaitForNetworkReady(ctx, tc.IPs))
		})
	}
}
