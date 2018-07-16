// Copyright 2018 ETH Zurich
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

package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
)

const (
	defKeyFile  = "gen-certs/tls.key"
	defCertFile = "gen-certs/tls.pem"
	maxReadMsgs = 1 << 8
)

var _ infra.Transport = (*QuicTransport)(nil)

type receivedMessage struct {
	data common.RawBytes
	peer net.Addr
	err  error
}

// QuicTransport implements interface Transport by creating a QUIC connection around the given
// net.PacketConn. Since QUIC is a reliable protocol both Send methods will be reliable.
//
// The receiving is implemented using a listener that runs in a go function
// that sends the received data to the receive method.
type QuicTransport struct {
	conn          net.PacketConn
	listener      *quic.Listener
	recvChan      chan receivedMessage
	clientTLSConf *tls.Config
	exit          bool
}

// NewQuicTransport creates a new QuicTransport, this also create a listener to acccept data.
// In case the listener creation failed nil and the error is returned.
func NewQuicTransport(conn net.PacketConn, tlsCertFile, tlsCertKey string) (*QuicTransport, error) {
	servTLSConf, err := initTls(tlsCertFile, tlsCertKey)
	if err != nil {
		return nil, err
	}
	listener, err := quic.Listen(conn, servTLSConf, nil)
	if err != nil {
		return nil, err
	}
	clientTLSConf := servTLSConf.Clone()
	// Don't verify the server's cert, as we are not using the TLS PKI.
	clientTLSConf.InsecureSkipVerify = true

	t := &QuicTransport{
		conn:          conn,
		listener:      &listener,
		recvChan:      make(chan receivedMessage, maxReadMsgs),
		clientTLSConf: clientTLSConf,
	}
	go t.clientAcceptor()
	// just to make sure that the acceptor is running
	<-t.recvChan
	return t, nil
}

func (t *QuicTransport) clientAcceptor() {
	// just to make sure that the acceptor is running
	t.recvChan <- receivedMessage{}
	for {
		qsess, err := (*t.listener).Accept()
		if t.exit {
			break
		}
		if err != nil {
			log.Crit("Error during accept", "err", err)
			panic("Error during accept")
		}
		go t.handleClient(qsess)
	}
}

func (t *QuicTransport) handleClient(qsess quic.Session) {
	qstream, err := qsess.AcceptStream()
	if err != nil {
		log.Error("Unable to accept quic stream", "err", err)
		return
	}

	msg := receivedMessage{
		make(common.RawBytes, common.MaxMTU),
		qsess.RemoteAddr(),
		nil,
	}

	totalRead := 0
	for {
		// Receive data until client closes (err != nil)
		read, err := qstream.Read(msg.data[totalRead:])
		totalRead += read
		if err != nil {
			qer := qerr.ToQuicError(err)
			if qer.ErrorCode == qerr.PeerGoingAway ||
				qer.ErrorCode == qerr.NetworkIdleTimeout ||
				err == io.EOF {
				break
			}
			log.Error("Error while reading from stream", "err", err)
			msg.err = err
			break
		}
	}
	msg.data = msg.data[:totalRead]
	select {
	case t.recvChan <- msg:
		// Do nothing
	default:
		log.Warn("Receive queue full, dropped message", "msg", msg)
	}
}

// SendUnreliableMsgTo delegates to SendMsgTo
// FIXME(lukedirtwalker) SendUnreliableMsgTo makes no sense with a reliable connection, i.e. quic,
// since you will always have to setup a connection etc.
// If the peer is not listening this is a blocking operation for reliable connection,
// since you need to dial.
func (t *QuicTransport) SendUnreliableMsgTo(ctx context.Context, b common.RawBytes,
	address net.Addr) error {
	return t.SendMsgTo(ctx, b, address)
}

func (t *QuicTransport) SendMsgTo(ctx context.Context, b common.RawBytes,
	address net.Addr) error {
	qsess, err := quic.DialAddrContext(ctx, address.String(), t.clientTLSConf, nil)
	if err != nil {
		return err
	}
	qstream, err := qsess.OpenStreamSync()
	if err != nil {
		return err
	}
	defer qstream.Close()
	written, err := qstream.Write(b)
	if err != nil {
		return err
	}
	if written != len(b) {
		return common.NewBasicError("Could not write all data", nil)
	}
	return nil
}

func (t *QuicTransport) RecvFrom(ctx context.Context) (common.RawBytes, net.Addr, error) {
	msg := <-t.recvChan
	log.Debug("Message recvd", "msg", string(msg.data))
	return msg.data, msg.peer, msg.err
}

func (t *QuicTransport) Close(context.Context) error {
	t.exit = true
	return (*t.listener).Close()
}

func initTls(tlsCertFile, tlsKeyFile string) (*tls.Config, error) {
	certFile := tlsCertFile
	if certFile == "" {
		certFile = defCertFile
	}
	keyFile := tlsKeyFile
	if keyFile == "" {
		keyFile = defKeyFile
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, common.NewBasicError("squic: Unable to load TLS cert/key", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
