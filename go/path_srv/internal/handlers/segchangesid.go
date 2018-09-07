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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/proto"
)

type segChangesIdHandler struct {
	*baseHandler
}

func NewSegChangesIDHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segChangesIdHandler{
			baseHandler: newBaseHandler(r, args),
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segChangesIdHandler) Handle() {
	segChangesIdReq, ok := h.request.Message.(*path_mgmt.SegChangesIdReq)
	if !ok {
		h.logger.Error(
			"[segChangesIdHandler] wrong message type, expected path_mgmt.SegChangesIDReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	h.logger.Debug("[segChangesIdHandler] Received", "segChangesIDReq", segChangesIdReq)
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		h.logger.Warn("[segChangesIdHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	lastCheck := time.Unix(int64(segChangesIdReq.LastCheck), 0)
	q := &query.Params{
		SegTypes:      []proto.PathSegType{proto.PathSegType_down},
		StartsAt:      []addr.IA{h.topology.ISD_AS},
		MinLastUpdate: &lastCheck,
	}
	res, err := h.pathDB.Get(subCtx, q)
	if err != nil {
		h.logger.Error("Failed to retrieve last changed ids", "err", err)
		// TODO send error reply?
		return
	}
	ids := extractSegIds(res)
	log.Debug("[segChangesIdHandler] found ids", "ids", ids)
	reply := &path_mgmt.SegChangesIdReply{
		Ids: ids,
	}
	err = msger.SendSegChangesIdReply(subCtx, reply, h.request.Peer, h.request.ID)
	if err != nil {
		h.logger.Error("[segChangesIdHandler] Failed to send reply!", "err", err)
	}
	h.logger.Debug("[segChangesIdHandler] reply sent", "id", h.request.ID)
}

func extractSegIds(res []*query.Result) []*path_mgmt.SegIds {
	ids := make([]*path_mgmt.SegIds, len(res))
	for i, r := range res {
		id, err := r.Seg.ID()
		if err != nil {
			// path DB should only contains valid segs
			panic(err)
		}
		fullId, err := r.Seg.FullId()
		if err != nil {
			// path DB should only contains valid segs
			panic(err)
		}
		ids[i] = &path_mgmt.SegIds{
			SegId:  id,
			FullId: fullId,
		}
	}
	return ids
}
