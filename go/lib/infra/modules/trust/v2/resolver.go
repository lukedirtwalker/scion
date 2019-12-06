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

package trust

import (
	"context"
	"net"

	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	// ErrResolveSuperseded indicates that the latest locally available TRC
	// supersedes the TRC to resolve.
	ErrResolveSuperseded = serrors.New("latest locally available is newer")
	// ErrInvalidResponse indicates an invalid response to an RPC call.
	ErrInvalidResponse = serrors.New("invalid RPC response")
)

// Resolver resolves verified trust material.
type Resolver interface {
	// TRC resolves the decoded signed TRC. Missing links in the TRC
	// verification chain are also requested.
	TRC(ctx context.Context, req TRCReq, server net.Addr) (decoded.TRC, error)
	// Chain resolves the raw signed certificate chain. If the issuing TRC is
	// missing, it is also requested.
	Chain(ctx context.Context, req ChainReq, server net.Addr) (decoded.Chain, error)
}

// resolver resolves trust material.
type resolver struct {
	db       DBRead
	inserter Inserter
	rpc      RPC
}

func (r *resolver) TRC(ctx context.Context, req TRCReq, server net.Addr) (decoded.TRC, error) {
	if req.Version.IsLatest() {
		latest, err := r.resolveLatestVersion(ctx, req, server)
		if err != nil {
			return decoded.TRC{}, serrors.WrapStr("unable to resolve latest version", err)
		}
		req = req.withVersion(latest)
	}
	prev, err := r.db.GetTRC(ctx, req.ISD, scrypto.LatestVer)
	if err != nil && !xerrors.Is(err, ErrNotFound) {
		return decoded.TRC{}, serrors.WrapStr("error fetching latest locally available TRC", err)
	}
	if prev != nil && prev.Version >= req.Version {
		return decoded.TRC{}, serrors.WithCtx(ErrResolveSuperseded, "requested", req.Version,
			"latest", prev.Version)
	}
	min := scrypto.Version(1)
	// If a previous TRC was found, use that as base case.
	if err == nil {
		min = prev.Version + 1
	}
	// Use slice of channels because the ordering of TRC replies matters.
	results := make([]chan resOrErr, req.Version-min+1)
	for i := range results {
		// buffered channel to avoid go routine leak.
		results[i] = make(chan resOrErr, 1)
		ireq := req.withVersion(min + scrypto.Version(i))
		r.startFetchTRC(ctx, results[i], ireq, server)
	}
	var decTRC decoded.TRC
	var w prevWrap
	w.SetTRC(prev)
	for _, resC := range results {
		res := <-resC
		if res.Err != nil {
			return decoded.TRC{}, serrors.WrapStr("unable to fetch parts of TRC chain", err)
		}
		decTRC = res.Decoded
		if err = r.inserter.InsertTRC(ctx, decTRC, w.TRC); err != nil {
			return decoded.TRC{}, serrors.WrapStr("unable to insert parts of TRC chain", err,
				"trc", decTRC)
		}
		w.SetTRC(decTRC.TRC)
	}
	return decTRC, nil
}

// FIXME(roosd): Add RPC that resolves just the latest version instead of the
// full TRC.
func (r *resolver) resolveLatestVersion(ctx context.Context, req TRCReq,
	server net.Addr) (scrypto.Version, error) {

	rawTRC, err := r.rpc.GetTRC(ctx, req, server)
	if err != nil {
		return 0, serrors.WrapStr("unable to resolve latest TRC", err)
	}
	decTRC, err := decoded.DecodeTRC(rawTRC)
	if err != nil {
		return 0, serrors.WrapStr("error parsing latest TRC", err)
	}
	if err := r.trcCheck(req, decTRC.TRC); err != nil {
		return 0, serrors.Wrap(ErrInvalidResponse, err)
	}
	return decTRC.TRC.Version, nil
}

func (r *resolver) startFetchTRC(ctx context.Context, res chan<- resOrErr,
	req TRCReq, server net.Addr) {

	go func() {
		defer log.LogPanicAndExit()
		rawTRC, err := r.rpc.GetTRC(ctx, req, server)
		if err != nil {
			res <- resOrErr{Err: serrors.WrapStr("error requesting TRC", err,
				"isd", req.ISD, "version", req.Version)}
			return
		}
		decTRC, err := decoded.DecodeTRC(rawTRC)
		if err != nil {
			res <- resOrErr{Err: serrors.WrapStr("failed to parse TRC", err,
				"isd", req.ISD, "version", req.Version)}
			return
		}
		if err := r.trcCheck(req, decTRC.TRC); err != nil {
			res <- resOrErr{Err: serrors.Wrap(ErrInvalidResponse, err)}
			return
		}
		res <- resOrErr{Decoded: decTRC}
	}()
}

func (r *resolver) trcCheck(req TRCReq, t *trc.TRC) error {
	switch {
	case req.ISD != t.ISD:
		return serrors.New("wrong isd", "expected", req.ISD, "actual", t.ISD)
	case !req.Version.IsLatest() && req.Version != t.Version:
		return serrors.New("wrong version", "expected", req.Version, "actual", t.Version)
	}
	return nil
}

func (r *resolver) Chain(ctx context.Context, req ChainReq,
	server net.Addr) (decoded.Chain, error) {

	// TODO(roosd): implement
	return decoded.Chain{}, serrors.New("not implemented")
}

type resOrErr struct {
	Decoded decoded.TRC
	Err     error
}

// prevWrap provides one single previous TRC. It is used in the TRC chain
// verification to avoid unnecessary database access.
type prevWrap struct {
	prev *trc.TRC
}

func (w *prevWrap) SetTRC(prev *trc.TRC) {
	w.prev = prev
}

func (w *prevWrap) TRC(_ context.Context, isd addr.ISD, version scrypto.Version) (*trc.TRC, error) {
	if isd != w.prev.ISD || version != w.prev.Version {
		return nil, serrors.New("previous wrapper can only provide a single TRC",
			"expected_isd", w.prev.ISD, "expted_version", w.prev.Version,
			"actual_isd", isd, "actual_version", version)
	}
	return w.prev, nil
}
