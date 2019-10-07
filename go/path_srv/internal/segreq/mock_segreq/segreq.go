// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/path_srv/internal/segreq (interfaces: LocalInfo)

// Package mock_segreq is a generated GoMock package.
package mock_segreq

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	query "github.com/scionproto/scion/go/lib/pathdb/query"
)

// MockLocalInfo is a mock of LocalInfo interface
type MockLocalInfo struct {
	ctrl     *gomock.Controller
	recorder *MockLocalInfoMockRecorder
}

// MockLocalInfoMockRecorder is the mock recorder for MockLocalInfo
type MockLocalInfoMockRecorder struct {
	mock *MockLocalInfo
}

// NewMockLocalInfo creates a new mock instance
func NewMockLocalInfo(ctrl *gomock.Controller) *MockLocalInfo {
	mock := &MockLocalInfo{ctrl: ctrl}
	mock.recorder = &MockLocalInfoMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockLocalInfo) EXPECT() *MockLocalInfoMockRecorder {
	return m.recorder
}

// IsParamsLocal mocks base method
func (m *MockLocalInfo) IsParamsLocal(arg0 *query.Params) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsParamsLocal", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsParamsLocal indicates an expected call of IsParamsLocal
func (mr *MockLocalInfoMockRecorder) IsParamsLocal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsParamsLocal", reflect.TypeOf((*MockLocalInfo)(nil).IsParamsLocal), arg0)
}

// IsSegLocal mocks base method
func (m *MockLocalInfo) IsSegLocal(arg0 context.Context, arg1, arg2 addr.IA) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsSegLocal", arg0, arg1, arg2)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsSegLocal indicates an expected call of IsSegLocal
func (mr *MockLocalInfoMockRecorder) IsSegLocal(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsSegLocal", reflect.TypeOf((*MockLocalInfo)(nil).IsSegLocal), arg0, arg1, arg2)
}
