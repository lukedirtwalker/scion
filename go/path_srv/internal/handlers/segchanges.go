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

package handlers

import (
	"context"
	"fmt"

	"github.com/scionproto/scion/go/path_srv/internal/segutil"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/proto"
)

type segChangesHandler struct {
	*baseHandler
}

func NewSegChangesHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segChangesHandler{
			baseHandler: newBaseHandler(r, args),
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segChangesHandler) Handle() {
	segChangesReq, ok := h.request.Message.(*path_mgmt.SegChangesReq)
	if !ok {
		h.logger.Error(
			"[segChangesHandler] wrong message type, expected path_mgmt.SegChangesReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	h.logger.Debug("[segChangesHandler] Received", "segChangesReq", segChangesReq)
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		h.logger.Warn("[segChangesHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	q := &query.Params{
		SegIDs: segChangesReq.SegIds,
	}
	res, err := h.pathDB.Get(subCtx, q)
	if err != nil {
		h.logger.Error("Failed to get segments from DB", "err", err)
		return
	}
	segs := query.Results(res).Segs()
	recs := &path_mgmt.SegRecs{
		Recs:      h.collectSegs(nil, nil, segs),
		SRevInfos: segutil.RelevantRevInfos(h.revCache, segs),
	}
	reply := &path_mgmt.SegChangesReply{
		SegRecs: recs,
	}
	err = msger.SendSegChangesReply(subCtx, reply, h.request.Peer, h.request.ID)
	if err != nil {
		h.logger.Error("[segChangesHandler] Failed to send reply!", "err", err)
	}
	h.logger.Debug("[segChangesHandler] reply sent", "id", h.request.ID)
}

func (h *segChangesHandler) collectSegs(upSegs, coreSegs, downSegs []*seg.PathSegment) []*seg.Meta {
	recs := make([]*seg.Meta, 0, len(upSegs)+len(coreSegs)+len(downSegs))
	for i := range upSegs {
		s := upSegs[i]
		h.logger.Debug(fmt.Sprintf("[segChangesHandler:collectSegs] up %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs = append(recs, &seg.Meta{
			Type:    proto.PathSegType_up,
			Segment: s,
		})
	}
	for i := range coreSegs {
		s := coreSegs[i]
		h.logger.Debug(fmt.Sprintf("[segChangesHandler:collectSegs] core %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs = append(recs, &seg.Meta{
			Type:    proto.PathSegType_core,
			Segment: s,
		})
	}
	for i := range downSegs {
		s := downSegs[i]
		h.logger.Debug(fmt.Sprintf("[segChangesHandler:collectSegs] down %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs = append(recs, &seg.Meta{
			Type:    proto.PathSegType_down,
			Segment: s,
		})
	}
	return recs
}
