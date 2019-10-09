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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/scionproto/scion/go/lib/ctrl/seg"

	pathdbsqlite "github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	sqlite = flag.String("sqlite", "", "path to sqlite db")
	ids    = flag.String("ids", "", "A list of ids comma separated, e.g. 26664916f256,2e13f05771f7"+
		" If set exactly the ids will be printed otherwise everything in the DB")
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	flag.Parse()
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "Flags invalid: %s\n", err)
		return 1
	}
	pathDB, err := pathdbsqlite.New(*sqlite)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load DB: %s\n", err)
		return 1
	}
	entries, err := pathDB.GetAll(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read from DB: %s\n", err)
		return 1
	}
	ids := idsFromFlags()
	for entry := range entries {
		if entry.Err != nil {
			fmt.Fprintf(os.Stderr, "Failed during read: %s\n", err)
			return 1
		}
		if printSeg(ids, entry.Result.Seg) {
			fmt.Printf("%s type: %s, seg: %s\n",
				entry.Result.Seg.GetLoggingID(), entry.Result.Type, entry.Result.Seg)
		}
	}
	return 0
}

func validateFlags() error {
	if *sqlite == "" {
		return serrors.New("Missing sqlite flag")
	}
	return nil
}

func idsFromFlags() map[string]struct{} {
	if *ids == "" {
		return nil
	}
	parts := strings.Split(*ids, ",")
	results := make(map[string]struct{}, len(parts))
	for _, id := range parts {
		results[id] = struct{}{}
	}
	return results
}

func printSeg(ids map[string]struct{}, seg *seg.PathSegment) bool {
	if ids == nil {
		return true
	}
	_, ok := ids[seg.GetLoggingID()]
	return ok
}
