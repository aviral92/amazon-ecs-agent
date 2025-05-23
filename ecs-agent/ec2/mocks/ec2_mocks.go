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
// Source: github.com/aws/amazon-ecs-agent/ecs-agent/ec2 (interfaces: EC2MetadataClient,HttpClient,Client,ClientSDK)

// Package mock_ec2 is a generated GoMock package.
package mock_ec2

import (
	context "context"
	reflect "reflect"

	ec2 "github.com/aws/amazon-ecs-agent/ecs-agent/ec2"
	imds "github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	ec20 "github.com/aws/aws-sdk-go-v2/service/ec2"
	types "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	gomock "github.com/golang/mock/gomock"
)

// MockEC2MetadataClient is a mock of EC2MetadataClient interface.
type MockEC2MetadataClient struct {
	ctrl     *gomock.Controller
	recorder *MockEC2MetadataClientMockRecorder
}

// MockEC2MetadataClientMockRecorder is the mock recorder for MockEC2MetadataClient.
type MockEC2MetadataClientMockRecorder struct {
	mock *MockEC2MetadataClient
}

// NewMockEC2MetadataClient creates a new mock instance.
func NewMockEC2MetadataClient(ctrl *gomock.Controller) *MockEC2MetadataClient {
	mock := &MockEC2MetadataClient{ctrl: ctrl}
	mock.recorder = &MockEC2MetadataClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEC2MetadataClient) EXPECT() *MockEC2MetadataClientMockRecorder {
	return m.recorder
}

// AllENIMacs mocks base method.
func (m *MockEC2MetadataClient) AllENIMacs() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AllENIMacs")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AllENIMacs indicates an expected call of AllENIMacs.
func (mr *MockEC2MetadataClientMockRecorder) AllENIMacs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AllENIMacs", reflect.TypeOf((*MockEC2MetadataClient)(nil).AllENIMacs))
}

// AvailabilityZoneID mocks base method.
func (m *MockEC2MetadataClient) AvailabilityZoneID() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AvailabilityZoneID")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AvailabilityZoneID indicates an expected call of AvailabilityZoneID.
func (mr *MockEC2MetadataClientMockRecorder) AvailabilityZoneID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AvailabilityZoneID", reflect.TypeOf((*MockEC2MetadataClient)(nil).AvailabilityZoneID))
}

// DefaultCredentials mocks base method.
func (m *MockEC2MetadataClient) DefaultCredentials() (*ec2.RoleCredentials, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DefaultCredentials")
	ret0, _ := ret[0].(*ec2.RoleCredentials)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DefaultCredentials indicates an expected call of DefaultCredentials.
func (mr *MockEC2MetadataClientMockRecorder) DefaultCredentials() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DefaultCredentials", reflect.TypeOf((*MockEC2MetadataClient)(nil).DefaultCredentials))
}

// GetDynamicData mocks base method.
func (m *MockEC2MetadataClient) GetDynamicData(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDynamicData", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDynamicData indicates an expected call of GetDynamicData.
func (mr *MockEC2MetadataClientMockRecorder) GetDynamicData(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDynamicData", reflect.TypeOf((*MockEC2MetadataClient)(nil).GetDynamicData), arg0)
}

// GetMetadata mocks base method.
func (m *MockEC2MetadataClient) GetMetadata(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMetadata", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMetadata indicates an expected call of GetMetadata.
func (mr *MockEC2MetadataClientMockRecorder) GetMetadata(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMetadata", reflect.TypeOf((*MockEC2MetadataClient)(nil).GetMetadata), arg0)
}

// GetUserData mocks base method.
func (m *MockEC2MetadataClient) GetUserData() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserData")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserData indicates an expected call of GetUserData.
func (mr *MockEC2MetadataClientMockRecorder) GetUserData() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserData", reflect.TypeOf((*MockEC2MetadataClient)(nil).GetUserData))
}

// InstanceID mocks base method.
func (m *MockEC2MetadataClient) InstanceID() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstanceID")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InstanceID indicates an expected call of InstanceID.
func (mr *MockEC2MetadataClientMockRecorder) InstanceID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstanceID", reflect.TypeOf((*MockEC2MetadataClient)(nil).InstanceID))
}

// InstanceIdentityDocument mocks base method.
func (m *MockEC2MetadataClient) InstanceIdentityDocument() (imds.InstanceIdentityDocument, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstanceIdentityDocument")
	ret0, _ := ret[0].(imds.InstanceIdentityDocument)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InstanceIdentityDocument indicates an expected call of InstanceIdentityDocument.
func (mr *MockEC2MetadataClientMockRecorder) InstanceIdentityDocument() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstanceIdentityDocument", reflect.TypeOf((*MockEC2MetadataClient)(nil).InstanceIdentityDocument))
}

// OutpostARN mocks base method.
func (m *MockEC2MetadataClient) OutpostARN() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OutpostARN")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OutpostARN indicates an expected call of OutpostARN.
func (mr *MockEC2MetadataClientMockRecorder) OutpostARN() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OutpostARN", reflect.TypeOf((*MockEC2MetadataClient)(nil).OutpostARN))
}

// PrimaryENIMAC mocks base method.
func (m *MockEC2MetadataClient) PrimaryENIMAC() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrimaryENIMAC")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PrimaryENIMAC indicates an expected call of PrimaryENIMAC.
func (mr *MockEC2MetadataClientMockRecorder) PrimaryENIMAC() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrimaryENIMAC", reflect.TypeOf((*MockEC2MetadataClient)(nil).PrimaryENIMAC))
}

// PrivateIPv4Address mocks base method.
func (m *MockEC2MetadataClient) PrivateIPv4Address() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrivateIPv4Address")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PrivateIPv4Address indicates an expected call of PrivateIPv4Address.
func (mr *MockEC2MetadataClientMockRecorder) PrivateIPv4Address() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrivateIPv4Address", reflect.TypeOf((*MockEC2MetadataClient)(nil).PrivateIPv4Address))
}

// PublicIPv4Address mocks base method.
func (m *MockEC2MetadataClient) PublicIPv4Address() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublicIPv4Address")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PublicIPv4Address indicates an expected call of PublicIPv4Address.
func (mr *MockEC2MetadataClientMockRecorder) PublicIPv4Address() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublicIPv4Address", reflect.TypeOf((*MockEC2MetadataClient)(nil).PublicIPv4Address))
}

// Region mocks base method.
func (m *MockEC2MetadataClient) Region() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Region")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Region indicates an expected call of Region.
func (mr *MockEC2MetadataClientMockRecorder) Region() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Region", reflect.TypeOf((*MockEC2MetadataClient)(nil).Region))
}

// SpotInstanceAction mocks base method.
func (m *MockEC2MetadataClient) SpotInstanceAction() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SpotInstanceAction")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SpotInstanceAction indicates an expected call of SpotInstanceAction.
func (mr *MockEC2MetadataClientMockRecorder) SpotInstanceAction() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SpotInstanceAction", reflect.TypeOf((*MockEC2MetadataClient)(nil).SpotInstanceAction))
}

// SubnetID mocks base method.
func (m *MockEC2MetadataClient) SubnetID(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SubnetID", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SubnetID indicates an expected call of SubnetID.
func (mr *MockEC2MetadataClientMockRecorder) SubnetID(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SubnetID", reflect.TypeOf((*MockEC2MetadataClient)(nil).SubnetID), arg0)
}

// TargetLifecycleState mocks base method.
func (m *MockEC2MetadataClient) TargetLifecycleState() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TargetLifecycleState")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// TargetLifecycleState indicates an expected call of TargetLifecycleState.
func (mr *MockEC2MetadataClientMockRecorder) TargetLifecycleState() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TargetLifecycleState", reflect.TypeOf((*MockEC2MetadataClient)(nil).TargetLifecycleState))
}

// VPCID mocks base method.
func (m *MockEC2MetadataClient) VPCID(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VPCID", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VPCID indicates an expected call of VPCID.
func (mr *MockEC2MetadataClientMockRecorder) VPCID(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VPCID", reflect.TypeOf((*MockEC2MetadataClient)(nil).VPCID), arg0)
}

// MockHttpClient is a mock of HttpClient interface.
type MockHttpClient struct {
	ctrl     *gomock.Controller
	recorder *MockHttpClientMockRecorder
}

// MockHttpClientMockRecorder is the mock recorder for MockHttpClient.
type MockHttpClientMockRecorder struct {
	mock *MockHttpClient
}

// NewMockHttpClient creates a new mock instance.
func NewMockHttpClient(ctrl *gomock.Controller) *MockHttpClient {
	mock := &MockHttpClient{ctrl: ctrl}
	mock.recorder = &MockHttpClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockHttpClient) EXPECT() *MockHttpClientMockRecorder {
	return m.recorder
}

// GetDynamicData mocks base method.
func (m *MockHttpClient) GetDynamicData(arg0 context.Context, arg1 *imds.GetDynamicDataInput, arg2 ...func(*imds.Options)) (*imds.GetDynamicDataOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetDynamicData", varargs...)
	ret0, _ := ret[0].(*imds.GetDynamicDataOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDynamicData indicates an expected call of GetDynamicData.
func (mr *MockHttpClientMockRecorder) GetDynamicData(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDynamicData", reflect.TypeOf((*MockHttpClient)(nil).GetDynamicData), varargs...)
}

// GetInstanceIdentityDocument mocks base method.
func (m *MockHttpClient) GetInstanceIdentityDocument(arg0 context.Context, arg1 *imds.GetInstanceIdentityDocumentInput, arg2 ...func(*imds.Options)) (*imds.GetInstanceIdentityDocumentOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetInstanceIdentityDocument", varargs...)
	ret0, _ := ret[0].(*imds.GetInstanceIdentityDocumentOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInstanceIdentityDocument indicates an expected call of GetInstanceIdentityDocument.
func (mr *MockHttpClientMockRecorder) GetInstanceIdentityDocument(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInstanceIdentityDocument", reflect.TypeOf((*MockHttpClient)(nil).GetInstanceIdentityDocument), varargs...)
}

// GetMetadata mocks base method.
func (m *MockHttpClient) GetMetadata(arg0 context.Context, arg1 *imds.GetMetadataInput, arg2 ...func(*imds.Options)) (*imds.GetMetadataOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetMetadata", varargs...)
	ret0, _ := ret[0].(*imds.GetMetadataOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMetadata indicates an expected call of GetMetadata.
func (mr *MockHttpClientMockRecorder) GetMetadata(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMetadata", reflect.TypeOf((*MockHttpClient)(nil).GetMetadata), varargs...)
}

// GetRegion mocks base method.
func (m *MockHttpClient) GetRegion(arg0 context.Context, arg1 *imds.GetRegionInput, arg2 ...func(*imds.Options)) (*imds.GetRegionOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetRegion", varargs...)
	ret0, _ := ret[0].(*imds.GetRegionOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRegion indicates an expected call of GetRegion.
func (mr *MockHttpClientMockRecorder) GetRegion(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRegion", reflect.TypeOf((*MockHttpClient)(nil).GetRegion), varargs...)
}

// GetUserData mocks base method.
func (m *MockHttpClient) GetUserData(arg0 context.Context, arg1 *imds.GetUserDataInput, arg2 ...func(*imds.Options)) (*imds.GetUserDataOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUserData", varargs...)
	ret0, _ := ret[0].(*imds.GetUserDataOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserData indicates an expected call of GetUserData.
func (mr *MockHttpClientMockRecorder) GetUserData(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserData", reflect.TypeOf((*MockHttpClient)(nil).GetUserData), varargs...)
}

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// CreateTags mocks base method.
func (m *MockClient) CreateTags(arg0 *ec20.CreateTagsInput) (*ec20.CreateTagsOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateTags", arg0)
	ret0, _ := ret[0].(*ec20.CreateTagsOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTags indicates an expected call of CreateTags.
func (mr *MockClientMockRecorder) CreateTags(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTags", reflect.TypeOf((*MockClient)(nil).CreateTags), arg0)
}

// DescribeECSTagsForInstance mocks base method.
func (m *MockClient) DescribeECSTagsForInstance(arg0 string) ([]types.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DescribeECSTagsForInstance", arg0)
	ret0, _ := ret[0].([]types.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DescribeECSTagsForInstance indicates an expected call of DescribeECSTagsForInstance.
func (mr *MockClientMockRecorder) DescribeECSTagsForInstance(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DescribeECSTagsForInstance", reflect.TypeOf((*MockClient)(nil).DescribeECSTagsForInstance), arg0)
}

// MockClientSDK is a mock of ClientSDK interface.
type MockClientSDK struct {
	ctrl     *gomock.Controller
	recorder *MockClientSDKMockRecorder
}

// MockClientSDKMockRecorder is the mock recorder for MockClientSDK.
type MockClientSDKMockRecorder struct {
	mock *MockClientSDK
}

// NewMockClientSDK creates a new mock instance.
func NewMockClientSDK(ctrl *gomock.Controller) *MockClientSDK {
	mock := &MockClientSDK{ctrl: ctrl}
	mock.recorder = &MockClientSDKMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientSDK) EXPECT() *MockClientSDKMockRecorder {
	return m.recorder
}

// CreateTags mocks base method.
func (m *MockClientSDK) CreateTags(arg0 context.Context, arg1 *ec20.CreateTagsInput, arg2 ...func(*ec20.Options)) (*ec20.CreateTagsOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateTags", varargs...)
	ret0, _ := ret[0].(*ec20.CreateTagsOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTags indicates an expected call of CreateTags.
func (mr *MockClientSDKMockRecorder) CreateTags(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTags", reflect.TypeOf((*MockClientSDK)(nil).CreateTags), varargs...)
}

// DescribeTags mocks base method.
func (m *MockClientSDK) DescribeTags(arg0 context.Context, arg1 *ec20.DescribeTagsInput, arg2 ...func(*ec20.Options)) (*ec20.DescribeTagsOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DescribeTags", varargs...)
	ret0, _ := ret[0].(*ec20.DescribeTagsOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DescribeTags indicates an expected call of DescribeTags.
func (mr *MockClientSDKMockRecorder) DescribeTags(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DescribeTags", reflect.TypeOf((*MockClientSDK)(nil).DescribeTags), varargs...)
}
