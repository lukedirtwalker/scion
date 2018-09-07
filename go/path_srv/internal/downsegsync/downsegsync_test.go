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
	"testing"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"

	"github.com/scionproto/scion/go/lib/ctrl/seg"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	g = graph.NewDefaultGraph()

	seg220_221 = g.Beacon([]common.IFIDType{2224})
	seg220_222 = g.Beacon([]common.IFIDType{2224, 2426})
)

// SegId returns the ps' Id and fails the test on error.
func SegId(t *testing.T, ps *seg.PathSegment) common.RawBytes {
	id, err := ps.ID()
	xtest.FailOnErr(t, err)
	return id
}

// FullId returns the ps' FullId and fails the test on error.
func FullId(t *testing.T, ps *seg.PathSegment) common.RawBytes {
	id, err := ps.FullId()
	xtest.FailOnErr(t, err)
	return id
}

func segsToIds(t *testing.T, segs ...*seg.PathSegment) []common.RawBytes {
	ids := make([]common.RawBytes, 0, len(segs))
	for _, ps := range segs {
		id := SegId(t, ps)
		ids = append(ids, id)
	}
	return ids
}

func segsToSegsIds(t *testing.T, segs ...*seg.PathSegment) []*path_mgmt.SegIds {
	ids := make([]*path_mgmt.SegIds, 0, len(segs))
	for _, ps := range segs {
		id := SegId(t, ps)
		fullId := FullId(t, ps)
		ids = append(ids, &path_mgmt.SegIds{SegId: id, FullId: fullId})
	}
	return ids
}

// withPeering returns ps's with an additional random peering hop, to change the fullId.
func withPeering(t *testing.T, ps *seg.PathSegment) *seg.PathSegment {
	fAs := ps.FirstIA().String()
	g.AddLink(fAs, 3551, "1-ff00:0:132", 3552, true)

	var ifIds []common.IFIDType
	for _, asEntry := range ps.ASEntries {
		he := asEntry.HopEntries[0]
		hf, err := he.HopField()
		xtest.FailOnErr(t, err)
		// Only use cons egress to recover the original ifids we used when creating the seg.
		if hf.ConsEgress > 0 {
			ifIds = append(ifIds, hf.ConsEgress)
		}
	}
	newPs := g.Beacon(ifIds)
	if !bytes.Equal(SegId(t, newPs), SegId(t, ps)) {
		t.Fatalf("Failed to create new Seg, ID differs")
	}
	if bytes.Equal(FullId(t, newPs), FullId(t, ps)) {
		t.Fatalf("Failed to create new Seg, FullId is same")
	}
	return newPs
}

func Test_DetermineIdsToFetch(t *testing.T) {
	testcases := []struct {
		Name     string
		SegIds   []*path_mgmt.SegIds
		DbSegs   []*seg.PathSegment
		Expected []common.RawBytes
	}{
		{
			Name: "Empty, empty -> empty",
		},
		{
			Name:     "Only ids -> ids",
			SegIds:   segsToSegsIds(t, seg220_221, seg220_222),
			Expected: segsToIds(t, seg220_221, seg220_222),
		},
		{
			Name:   "All in DB -> empty",
			SegIds: segsToSegsIds(t, seg220_221, seg220_222),
			DbSegs: []*seg.PathSegment{seg220_221, seg220_222},
		},
		{
			Name:     "DB contains on -> other Ids returned",
			SegIds:   segsToSegsIds(t, seg220_221, seg220_222),
			DbSegs:   []*seg.PathSegment{seg220_221},
			Expected: segsToIds(t, seg220_222),
		},
		{
			Name:     "DB contains seg with different fullId -> differing",
			SegIds:   segsToSegsIds(t, seg220_221, seg220_222),
			DbSegs:   []*seg.PathSegment{seg220_221, withPeering(t, seg220_222)},
			Expected: segsToIds(t, seg220_222),
		},
	}
	Convey("Test determine ids to fetch", t, func() {
		for _, tc := range testcases {
			Convey(tc.Name, func() {
				ids := determineIdsToFetch(tc.SegIds, tc.DbSegs)
				SoMsg("Ids", ids, ShouldResemble, tc.Expected)
			})
		}
	})
}
