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

package segreq_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/path_srv/internal/segreq"
)

func TestSegSelector(t *testing.T) {
	tests := map[string]struct {
		PrepareMocks   func(db *mock_pathdb.MockPathDB) []*seg.PathSegment
		ErrorAssertion require.ErrorAssertionFunc
	}{
		"PathDB error": {
			PrepareMocks: func(db *mock_pathdb.MockPathDB) []*seg.PathSegment {

				db.EXPECT().Get(gomock.Any(), gomock.Any()).Return(nil, errors.New("test err"))
				return nil
			},
			ErrorAssertion: require.Error,
		},
		"No segments": {
			PrepareMocks: func(db *mock_pathdb.MockPathDB,
			) []*seg.PathSegment {
				db.EXPECT().Get(gomock.Any(), gomock.Any()).Return(nil, nil)
				return nil
			},
			ErrorAssertion: require.Error,
		},
		"Segments": {
			PrepareMocks: func(db *mock_pathdb.MockPathDB,
			) []*seg.PathSegment {

				seg1 := &seg.PathSegment{RawSData: []byte{1}}
				seg2 := &seg.PathSegment{RawSData: []byte{2}}
				seg3 := &seg.PathSegment{RawSData: []byte{3}}
				results := query.Results{
					&query.Result{Seg: seg1},
					&query.Result{Seg: seg2},
					&query.Result{Seg: seg3},
				}
				db.EXPECT().Get(gomock.Any(), gomock.Any()).Return(results, nil)
				return []*seg.PathSegment{seg1, seg2, seg3}
			},
			ErrorAssertion: require.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			db := mock_pathdb.NewMockPathDB(ctrl)
			possibleSegs := test.PrepareMocks(db)
			s := segreq.SegSelector{
				PathDB: db,
			}
			seg, err := s.SelectSeg(context.Background(), &query.Params{})
			test.ErrorAssertion(t, err)
			if len(possibleSegs) > 0 {
				assert.Contains(t, possibleSegs, seg)
			}
		})
	}
}
