// Code generated by pegomock. DO NOT EDIT.
package matchers

import (
	gits "github.com/jiubian-cicd/env-controller/pkg/gits"
	"github.com/petergtz/pegomock"
	"reflect"
)

func AnySliceOfPtrToGitsGitRepoStatus() []*gits.GitRepoStatus {
	pegomock.RegisterMatcher(pegomock.NewAnyMatcher(reflect.TypeOf((*([]*gits.GitRepoStatus))(nil)).Elem()))
	var nullValue []*gits.GitRepoStatus
	return nullValue
}

func EqSliceOfPtrToGitsGitRepoStatus(value []*gits.GitRepoStatus) []*gits.GitRepoStatus {
	pegomock.RegisterMatcher(&pegomock.EqMatcher{Value: value})
	var nullValue []*gits.GitRepoStatus
	return nullValue
}
