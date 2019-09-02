// Code generated by pegomock. DO NOT EDIT.
// Source: github.com/jiubian-cicd/env-controller/pkg/gits (interfaces: OrganisationLister)

package gits_test

import (
	gits "github.com/jiubian-cicd/env-controller/pkg/gits"
	pegomock "github.com/petergtz/pegomock"
	"reflect"
	"time"
)

type MockOrganisationLister struct {
	fail func(message string, callerSkip ...int)
}

func NewMockOrganisationLister(options ...pegomock.Option) *MockOrganisationLister {
	mock := &MockOrganisationLister{}
	for _, option := range options {
		option.Apply(mock)
	}
	return mock
}

func (mock *MockOrganisationLister) SetFailHandler(fh pegomock.FailHandler) { mock.fail = fh }
func (mock *MockOrganisationLister) FailHandler() pegomock.FailHandler      { return mock.fail }

func (mock *MockOrganisationLister) ListOrganisations() ([]gits.GitOrganisation, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockOrganisationLister().")
	}
	params := []pegomock.Param{}
	result := pegomock.GetGenericMockFrom(mock).Invoke("ListOrganisations", params, []reflect.Type{reflect.TypeOf((*[]gits.GitOrganisation)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var ret0 []gits.GitOrganisation
	var ret1 error
	if len(result) != 0 {
		if result[0] != nil {
			ret0 = result[0].([]gits.GitOrganisation)
		}
		if result[1] != nil {
			ret1 = result[1].(error)
		}
	}
	return ret0, ret1
}

func (mock *MockOrganisationLister) VerifyWasCalledOnce() *VerifierMockOrganisationLister {
	return &VerifierMockOrganisationLister{
		mock:                   mock,
		invocationCountMatcher: pegomock.Times(1),
	}
}

func (mock *MockOrganisationLister) VerifyWasCalled(invocationCountMatcher pegomock.Matcher) *VerifierMockOrganisationLister {
	return &VerifierMockOrganisationLister{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
	}
}

func (mock *MockOrganisationLister) VerifyWasCalledInOrder(invocationCountMatcher pegomock.Matcher, inOrderContext *pegomock.InOrderContext) *VerifierMockOrganisationLister {
	return &VerifierMockOrganisationLister{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
		inOrderContext:         inOrderContext,
	}
}

func (mock *MockOrganisationLister) VerifyWasCalledEventually(invocationCountMatcher pegomock.Matcher, timeout time.Duration) *VerifierMockOrganisationLister {
	return &VerifierMockOrganisationLister{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
		timeout:                timeout,
	}
}

type VerifierMockOrganisationLister struct {
	mock                   *MockOrganisationLister
	invocationCountMatcher pegomock.Matcher
	inOrderContext         *pegomock.InOrderContext
	timeout                time.Duration
}

func (verifier *VerifierMockOrganisationLister) ListOrganisations() *MockOrganisationLister_ListOrganisations_OngoingVerification {
	params := []pegomock.Param{}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "ListOrganisations", params, verifier.timeout)
	return &MockOrganisationLister_ListOrganisations_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockOrganisationLister_ListOrganisations_OngoingVerification struct {
	mock              *MockOrganisationLister
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockOrganisationLister_ListOrganisations_OngoingVerification) GetCapturedArguments() {
}

func (c *MockOrganisationLister_ListOrganisations_OngoingVerification) GetAllCapturedArguments() {
}
