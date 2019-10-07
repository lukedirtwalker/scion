// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/sig/egress/iface (interfaces: Session)

// Package mock_iface is a generated GoMock package.
package mock_iface

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	log "github.com/scionproto/scion/go/lib/log"
	ringbuf "github.com/scionproto/scion/go/lib/ringbuf"
	snet "github.com/scionproto/scion/go/lib/snet"
	iface "github.com/scionproto/scion/go/sig/egress/iface"
	mgmt "github.com/scionproto/scion/go/sig/mgmt"
)

// MockSession is a mock of Session interface
type MockSession struct {
	ctrl     *gomock.Controller
	recorder *MockSessionMockRecorder
}

// MockSessionMockRecorder is the mock recorder for MockSession
type MockSessionMockRecorder struct {
	mock *MockSession
}

// NewMockSession creates a new mock instance
func NewMockSession(ctrl *gomock.Controller) *MockSession {
	mock := &MockSession{ctrl: ctrl}
	mock.recorder = &MockSessionMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSession) EXPECT() *MockSessionMockRecorder {
	return m.recorder
}

// AnnounceWorkerStopped mocks base method
func (m *MockSession) AnnounceWorkerStopped() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AnnounceWorkerStopped")
}

// AnnounceWorkerStopped indicates an expected call of AnnounceWorkerStopped
func (mr *MockSessionMockRecorder) AnnounceWorkerStopped() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AnnounceWorkerStopped", reflect.TypeOf((*MockSession)(nil).AnnounceWorkerStopped))
}

// Cleanup mocks base method
func (m *MockSession) Cleanup() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Cleanup")
	ret0, _ := ret[0].(error)
	return ret0
}

// Cleanup indicates an expected call of Cleanup
func (mr *MockSessionMockRecorder) Cleanup() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cleanup", reflect.TypeOf((*MockSession)(nil).Cleanup))
}

// Conn mocks base method
func (m *MockSession) Conn() snet.Conn {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Conn")
	ret0, _ := ret[0].(snet.Conn)
	return ret0
}

// Conn indicates an expected call of Conn
func (mr *MockSessionMockRecorder) Conn() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Conn", reflect.TypeOf((*MockSession)(nil).Conn))
}

// Crit mocks base method
func (m *MockSession) Crit(arg0 string, arg1 ...interface{}) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Crit", varargs...)
}

// Crit indicates an expected call of Crit
func (mr *MockSessionMockRecorder) Crit(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Crit", reflect.TypeOf((*MockSession)(nil).Crit), varargs...)
}

// Debug mocks base method
func (m *MockSession) Debug(arg0 string, arg1 ...interface{}) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Debug", varargs...)
}

// Debug indicates an expected call of Debug
func (mr *MockSessionMockRecorder) Debug(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Debug", reflect.TypeOf((*MockSession)(nil).Debug), varargs...)
}

// Error mocks base method
func (m *MockSession) Error(arg0 string, arg1 ...interface{}) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Error", varargs...)
}

// Error indicates an expected call of Error
func (mr *MockSessionMockRecorder) Error(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Error", reflect.TypeOf((*MockSession)(nil).Error), varargs...)
}

// GetHandler mocks base method
func (m *MockSession) GetHandler() log.Handler {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetHandler")
	ret0, _ := ret[0].(log.Handler)
	return ret0
}

// GetHandler indicates an expected call of GetHandler
func (mr *MockSessionMockRecorder) GetHandler() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHandler", reflect.TypeOf((*MockSession)(nil).GetHandler))
}

// Healthy mocks base method
func (m *MockSession) Healthy() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Healthy")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Healthy indicates an expected call of Healthy
func (mr *MockSessionMockRecorder) Healthy() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Healthy", reflect.TypeOf((*MockSession)(nil).Healthy))
}

// IA mocks base method
func (m *MockSession) IA() addr.IA {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IA")
	ret0, _ := ret[0].(addr.IA)
	return ret0
}

// IA indicates an expected call of IA
func (mr *MockSessionMockRecorder) IA() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IA", reflect.TypeOf((*MockSession)(nil).IA))
}

// ID mocks base method
func (m *MockSession) ID() mgmt.SessionType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ID")
	ret0, _ := ret[0].(mgmt.SessionType)
	return ret0
}

// ID indicates an expected call of ID
func (mr *MockSessionMockRecorder) ID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ID", reflect.TypeOf((*MockSession)(nil).ID))
}

// Info mocks base method
func (m *MockSession) Info(arg0 string, arg1 ...interface{}) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Info", varargs...)
}

// Info indicates an expected call of Info
func (mr *MockSessionMockRecorder) Info(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Info", reflect.TypeOf((*MockSession)(nil).Info), varargs...)
}

// New mocks base method
func (m *MockSession) New(arg0 ...interface{}) log.Logger {
	m.ctrl.T.Helper()
	varargs := []interface{}{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(log.Logger)
	return ret0
}

// New indicates an expected call of New
func (mr *MockSessionMockRecorder) New(arg0 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockSession)(nil).New), arg0...)
}

// PathPool mocks base method
func (m *MockSession) PathPool() iface.PathPool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PathPool")
	ret0, _ := ret[0].(iface.PathPool)
	return ret0
}

// PathPool indicates an expected call of PathPool
func (mr *MockSessionMockRecorder) PathPool() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PathPool", reflect.TypeOf((*MockSession)(nil).PathPool))
}

// Remote mocks base method
func (m *MockSession) Remote() *iface.RemoteInfo {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remote")
	ret0, _ := ret[0].(*iface.RemoteInfo)
	return ret0
}

// Remote indicates an expected call of Remote
func (mr *MockSessionMockRecorder) Remote() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remote", reflect.TypeOf((*MockSession)(nil).Remote))
}

// Ring mocks base method
func (m *MockSession) Ring() *ringbuf.Ring {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Ring")
	ret0, _ := ret[0].(*ringbuf.Ring)
	return ret0
}

// Ring indicates an expected call of Ring
func (mr *MockSessionMockRecorder) Ring() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Ring", reflect.TypeOf((*MockSession)(nil).Ring))
}

// SetHandler mocks base method
func (m *MockSession) SetHandler(arg0 log.Handler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetHandler", arg0)
}

// SetHandler indicates an expected call of SetHandler
func (mr *MockSessionMockRecorder) SetHandler(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetHandler", reflect.TypeOf((*MockSession)(nil).SetHandler), arg0)
}

// Trace mocks base method
func (m *MockSession) Trace(arg0 string, arg1 ...interface{}) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Trace", varargs...)
}

// Trace indicates an expected call of Trace
func (mr *MockSessionMockRecorder) Trace(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trace", reflect.TypeOf((*MockSession)(nil).Trace), varargs...)
}

// Warn mocks base method
func (m *MockSession) Warn(arg0 string, arg1 ...interface{}) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Warn", varargs...)
}

// Warn indicates an expected call of Warn
func (mr *MockSessionMockRecorder) Warn(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Warn", reflect.TypeOf((*MockSession)(nil).Warn), varargs...)
}
