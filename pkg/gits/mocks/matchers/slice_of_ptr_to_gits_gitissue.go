// Code generated by pegomock. DO NOT EDIT.
package matchers

import (
	gits "github.com/jiubian-cicd/env-controller/pkg/gits"
	"github.com/petergtz/pegomock"
	"reflect"
)

func AnySliceOfPtrToGitsGitIssue() []*gits.GitIssue {
	pegomock.RegisterMatcher(pegomock.NewAnyMatcher(reflect.TypeOf((*([]*gits.GitIssue))(nil)).Elem()))
	var nullValue []*gits.GitIssue
	return nullValue
}

func EqSliceOfPtrToGitsGitIssue(value []*gits.GitIssue) []*gits.GitIssue {
	pegomock.RegisterMatcher(&pegomock.EqMatcher{Value: value})
	var nullValue []*gits.GitIssue
	return nullValue
}
