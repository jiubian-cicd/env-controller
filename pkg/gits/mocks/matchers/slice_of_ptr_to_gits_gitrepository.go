// Code generated by pegomock. DO NOT EDIT.
package matchers

import (
	gits "github.com/jiubian-cicd/env-controller/pkg/gits"
	"github.com/petergtz/pegomock"
	"reflect"
)

func AnySliceOfPtrToGitsGitRepository() []*gits.GitRepository {
	pegomock.RegisterMatcher(pegomock.NewAnyMatcher(reflect.TypeOf((*([]*gits.GitRepository))(nil)).Elem()))
	var nullValue []*gits.GitRepository
	return nullValue
}

func EqSliceOfPtrToGitsGitRepository(value []*gits.GitRepository) []*gits.GitRepository {
	pegomock.RegisterMatcher(&pegomock.EqMatcher{Value: value})
	var nullValue []*gits.GitRepository
	return nullValue
}
