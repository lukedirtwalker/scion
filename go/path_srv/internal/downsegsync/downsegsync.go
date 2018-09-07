// Copyright 2018 Anapaya Systems
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

package downsegsync

import (
	"bytes"
	"context"
	"net"
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/segsaver"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/path_srv/internal/addrutil"
	"github.com/scionproto/scion/go/path_srv/internal/handlers"
	"github.com/scionproto/scion/go/path_srv/internal/periodic"
	"github.com/scionproto/scion/go/path_srv/internal/segutil"
	"github.com/scionproto/scion/go/proto"
)

var requestID messenger.Counter

var _ periodic.Task = (*downSegSync)(nil)

type downSegSync struct {
	lastSync   *time.Time
	pathDB     pathdb.PathDB
	revCache   revcache.RevCache
	msger      infra.Messenger
	trustStore infra.TrustStore
	topology   *topology.Topo
	localIA    addr.IA
	dstIA      addr.IA
	repErrCnt  int
}

func StartAll(args handlers.HandlerArgs, msger infra.Messenger) ([]*periodic.Runner, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	trc, err := args.TrustStore.GetTRC(ctx, args.Topology.ISD_AS.I, scrypto.LatestVer)
	if err != nil {
		return nil, common.NewBasicError("Failed to get local TRC", err)
	}
	segSyncers := make([]*periodic.Runner, 0, len(trc.CoreASes)-1)
	for coreAS := range trc.CoreASes {
		if coreAS.Eq(args.Topology.ISD_AS) {
			continue
		}
		syncer := &downSegSync{
			pathDB:     args.PathDB,
			revCache:   args.RevCache,
			topology:   args.Topology,
			trustStore: args.TrustStore,
			msger:      msger,
			dstIA:      coreAS,
			localIA:    args.Topology.ISD_AS,
		}
		// TODO(lukedirtwalker): either log or add metric to indicate
		// if task takes longer than ticker often.
		segSyncers = append(segSyncers, periodic.StartPeriodicTask(syncer,
			time.NewTicker(time.Second), 3*time.Second))
	}
	return segSyncers, nil
}

func (s *downSegSync) Run(ctx context.Context) {
	start := time.Now()
	// TODO(lukedirtwalker): handle too many errors in s.repErrCnt.
	cPs, err := s.getDstAddr(ctx)
	if err != nil {
		log.Error("[segsyncer] Failed to find path to remote", "dstIA", s.dstIA, "err", err)
		s.repErrCnt++
		return
	}
	cnt, err := s.runInternal(ctx, cPs)
	if err != nil {
		log.Error("[segsyncer] Failed to send segSync", "dstIA", s.dstIA, "err", err)
		s.repErrCnt++
		return
	}
	if cnt > 0 {
		log.Debug("[segsyncer] Sent down segments", "dstIA", s.dstIA, "cnt", cnt)
	}
	s.repErrCnt = 0
	s.lastSync = &start
}

func (s *downSegSync) getDstAddr(ctx context.Context) (net.Addr, error) {
	coreSegs, err := s.fetchCoreSegsFromDB(ctx)
	if err != nil {
		return nil, common.NewBasicError("Failed to get core segs", err)
	}
	if len(coreSegs) < 1 {
		return nil, common.NewBasicError("No core segments found!", nil)
	}
	var cPs net.Addr
	// select a seg to reach the dst
	for _, ps := range coreSegs {
		cPs, err = addrutil.GetPath(addr.SvcPS, ps, ps.FirstIA(), s.topology)
		if err == nil {
			return cPs, nil
		}
	}
	return nil, err
}

func (s *downSegSync) fetchCoreSegsFromDB(ctx context.Context) ([]*seg.PathSegment, error) {
	params := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
		StartsAt: []addr.IA{s.dstIA},
		EndsAt:   []addr.IA{s.localIA},
	}
	res, err := s.pathDB.Get(ctx, params)
	if err != nil {
		return nil, err
	}
	segs := query.Results(res).Segs()
	segs.FilterSegs(func(ps *seg.PathSegment) bool {
		return segutil.NoRevokedHopIntf(s.revCache, ps)
	})
	// Sort by number of hops, i.e. AS entries.
	sort.Slice(segs, func(i, j int) bool {
		return len(segs[i].ASEntries) < len(segs[j].ASEntries)
	})
	return segs, nil
}

func (s *downSegSync) runInternal(ctx context.Context, cPs net.Addr) (int, error) {
	log.Debug("Start sync of down segments", "dst", s.dstIA)
	msg := &path_mgmt.SegChangesIdReq{
		LastCheck: uint64(time.Now().Add(-30 * time.Minute).Unix()),
	}
	segChangesId, err := s.msger.GetSegChangesIds(ctx, msg, cPs, requestID.Next())
	if err != nil {
		return 0, common.NewBasicError("Failed to get changed Ids", err)
	}
	ids := segChangesId.Ids
	if len(ids) == 0 {
		log.Debug("Now ids received")
		return 0, nil
	}
	dbSegs, err := s.pathDB.Get(ctx, &query.Params{
		SegIDs: extractSegIds(ids),
	})
	if err != nil {
		return 0, common.NewBasicError("Failed to load segs from DB", err)
	}
	fetchIds := determineIdsToFetch(ids, query.Results(dbSegs).Segs())
	if len(fetchIds) == 0 {
		return 0, nil
	}
	changesReq := &path_mgmt.SegChangesReq{
		SegIds: fetchIds,
	}
	segChanges, err := s.msger.GetSegChanges(ctx, changesReq, cPs, requestID.Next())
	if err != nil {
		return 0, common.NewBasicError("Failed to get changed segs", err)
	}
	s.verifyAndStore(ctx, cPs, segChanges.Recs, segChanges.SRevInfos)
	// TODO return the amount of inserted segs
	return 0, nil
}

// TODO copy of handler code!
func (s *downSegSync) verifyAndStore(ctx context.Context, src net.Addr,
	recs []*seg.Meta, revInfos []*path_mgmt.SignedRevInfo) {
	// TODO(lukedirtwalker): collect the verified segs/revoc and return them.

	// verify and store the segments
	verifiedSeg := func(ctx context.Context, sMeta *seg.Meta) {
		if err := segsaver.StoreSeg(ctx, sMeta, s.pathDB, log.Root()); err != nil {
			log.Error("Unable to insert segment into path database",
				"seg", sMeta.Segment, "err", err)
		}
	}
	verifiedRev := func(ctx context.Context, rev *path_mgmt.SignedRevInfo) {
		segsaver.StoreRevocation(rev, s.revCache)
	}
	segErr := func(sMeta *seg.Meta, err error) {
		log.Warn("Segment verification failed", "segment", sMeta.Segment, "err", err)
	}
	revErr := func(revocation *path_mgmt.SignedRevInfo, err error) {
		log.Warn("Revocation verification failed", "revocation", revocation, "err", err)
	}
	segverifier.Verify(ctx, s.trustStore, src, recs,
		revInfos, verifiedSeg, verifiedRev, segErr, revErr)
}

func extractSegIds(ids []*path_mgmt.SegIds) []common.RawBytes {
	res := make([]common.RawBytes, len(ids))
	for i := range ids {
		res[i] = ids[i].SegId
	}
	return res
}

func determineIdsToFetch(segIds []*path_mgmt.SegIds, dbSegs []*seg.PathSegment) []common.RawBytes {
	var res []common.RawBytes
	for _, segId := range segIds {
		// TODO(lukedirtwalker): also check if segment is expired.
		segFullId := fullIdInSegs(dbSegs, segId.SegId)
		if !bytes.Equal(segId.FullId, segFullId) {
			res = append(res, segId.SegId)
		}
	}
	return res
}

func fullIdInSegs(segs []*seg.PathSegment, id common.RawBytes) common.RawBytes {
	for _, ps := range segs {
		segId, err := ps.ID()
		if err != nil {
			panic(err)
		}
		if bytes.Equal(segId, id) {
			fullID, err := ps.FullId()
			if err != nil {
				panic(err)
			}
			return fullID
		}
	}
	return nil
}
