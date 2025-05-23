// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/aws/amazon-ecs-agent/agent/fsx/factory (interfaces: FSxClientCreator)

// Package mock_factory is a generated GoMock package.
package mock_factory

import (
	reflect "reflect"

	fsx "github.com/aws/amazon-ecs-agent/agent/fsx"
	credentials "github.com/aws/amazon-ecs-agent/ecs-agent/credentials"
	gomock "github.com/golang/mock/gomock"
)

// MockFSxClientCreator is a mock of FSxClientCreator interface.
type MockFSxClientCreator struct {
	ctrl     *gomock.Controller
	recorder *MockFSxClientCreatorMockRecorder
}

// MockFSxClientCreatorMockRecorder is the mock recorder for MockFSxClientCreator.
type MockFSxClientCreatorMockRecorder struct {
	mock *MockFSxClientCreator
}

// NewMockFSxClientCreator creates a new mock instance.
func NewMockFSxClientCreator(ctrl *gomock.Controller) *MockFSxClientCreator {
	mock := &MockFSxClientCreator{ctrl: ctrl}
	mock.recorder = &MockFSxClientCreatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockFSxClientCreator) EXPECT() *MockFSxClientCreatorMockRecorder {
	return m.recorder
}

// NewFSxClient mocks base method.
func (m *MockFSxClientCreator) NewFSxClient(arg0 string, arg1 credentials.IAMRoleCredentials) (fsx.FSxClient, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewFSxClient", arg0, arg1)
	ret0, _ := ret[0].(fsx.FSxClient)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewFSxClient indicates an expected call of NewFSxClient.
func (mr *MockFSxClientCreatorMockRecorder) NewFSxClient(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewFSxClient", reflect.TypeOf((*MockFSxClientCreator)(nil).NewFSxClient), arg0, arg1)
}
