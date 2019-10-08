// Copyright 2019 ETH Zurich, Anapaya Systems
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

package snet

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// PacketDispatcherService constructs SCION sockets where applications have
// fine-grained control over header fields.
type PacketDispatcherService interface {
	RegisterTimeout(ia addr.IA, public *addr.AppAddr, bind *overlay.OverlayAddr,
		svc addr.HostSVC, timeout time.Duration) (PacketConn, uint16, error)
}

var _ PacketDispatcherService = (*DefaultPacketDispatcherService)(nil)

// DefaultPacketDispatcherService parses/serializes packets received from /
// sent to the dispatcher.
type DefaultPacketDispatcherService struct {
	// Dispatcher is used to get packets from the local SCION Dispatcher process.
	Dispatcher reliable.DispatcherService
	// SCMPHandler is invoked for packets that contain an SCMP L4. If the
	// handler is nil, errors are returned back to applications every time an
	// SCMP message is received.
	SCMPHandler SCMPHandler
}

func (s *DefaultPacketDispatcherService) RegisterTimeout(ia addr.IA, public *addr.AppAddr,
	bind *overlay.OverlayAddr, svc addr.HostSVC,
	timeout time.Duration) (PacketConn, uint16, error) {

	rconn, port, err := s.Dispatcher.RegisterTimeout(ia, public, bind, svc, timeout)
	if err != nil {
		return nil, 0, err
	}
	return &SCIONPacketConn{conn: rconn, scmpHandler: s.SCMPHandler}, port, err
}

// SCMPHandler customizes the way snet connections deal with SCMP.
type SCMPHandler interface {
	// Handle processes the packet as an SCMP packet. If packet is not SCMP, it
	// returns an error.
	//
	// If the handler returns an error value, snet will propagate the error
	// back to the caller. If the return value is nil, snet will reattempt to
	// read a data packet from the underlying dispatcher connection.
	//
	// Handlers that wish to ignore SCMP can just return nil.
	//
	// If the handler mutates the packet, the changes are seen by snet
	// connection method callers.
	Handle(pkt *SCIONPacket) error
}

// NewSCMPHandler creates a default SCMP handler that forwards revocations to
// the path resolver. SCMP packets are also forwarded to snet callers via
// errors returned by Read calls.
//
// If the resolver is nil, revocations are not forwarded to any resolver.
// However, they are still sent back to the caller during read operations.
func NewSCMPHandler(pr pathmgr.Resolver) SCMPHandler {
	return &scmpHandler{
		pathResolver: pr,
	}
}

// scmpHandler handles SCMP messages received from the network.
// If a resolver is configured, it is informed of any received revocations. All
// revocations are passed back to the caller embedded in the error, so
// applications can handle them manually.
type scmpHandler struct {
	// pathResolver manages revocations received via SCMP. If nil, nothing is informed.
	pathResolver pathmgr.Resolver
}

func (h *scmpHandler) Handle(pkt *SCIONPacket) error {
	hdr, ok := pkt.L4Header.(*scmp.Hdr)
	if !ok {
		return serrors.New("scmp handler invoked with non-scmp packet", "pkt", pkt)
	}

	// Only handle revocations for now
	if hdr.Class == scmp.C_Path && hdr.Type == scmp.T_P_RevokedIF {
		return h.handleSCMPRev(hdr, pkt)
	}
	log.Debug("Ignoring scmp packet", "hdr", hdr, "src", pkt.Source)
	return nil
}

func (h *scmpHandler) handleSCMPRev(hdr *scmp.Hdr, pkt *SCIONPacket) error {
	scmpPayload, ok := pkt.Payload.(*scmp.Payload)
	if !ok {
		return serrors.New("Unable to type assert payload to SCMP payload",
			"type", common.TypeOf(pkt.Payload))
	}
	info, ok := scmpPayload.Info.(*scmp.InfoRevocation)
	if !ok {
		return serrors.New("Unable to type assert SCMP Info to SCMP Revocation Info",
			"type", common.TypeOf(scmpPayload.Info))
	}
	log.Info("Received SCMP revocation", "header", hdr.String(), "payload", scmpPayload.String(),
		"src", pkt.Source)
	if h.pathResolver != nil {
		h.pathResolver.RevokeRaw(context.TODO(), info.RawSRev)
	}
	return &OpError{scmp: hdr}
}
