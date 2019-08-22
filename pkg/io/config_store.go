package io

import (
	"io/ioutil"

	"github.com/ghodss/yaml"
	"github.com/jiubian-cicd/env-controller/pkg/util"
	"github.com/pkg/errors"
)

// ConfigStore provides an interface for storing configs
type ConfigStore interface {
	// Write saves some secret data to the store
	Write(name string, bytes []byte) error

	// Read reads some secret data from the store
	Read(name string) ([]byte, error)

	// WriteObject writes a named object to the store
	WriteObject(name string, object interface{}) error

	// ReadObject reads an object from the store
	ReadObject(name string, object interface{}) error
}

type fileStore struct {
}

// NewFileStore creates a ConfigStore that stores its data to the filesystem
func NewFileStore() ConfigStore {
	return &fileStore{}
}

// Write writes a secret to the filesystem
func (f *fileStore) Write(fileName string, bytes []byte) error {
	return ioutil.WriteFile(fileName, bytes, util.DefaultWritePermissions)
}

// WriteObject writes a secret to the filesystem in YAML format
func (f *fileStore) WriteObject(fileName string, object interface{}) error {
	y, err := yaml.Marshal(object)
	if err != nil {
		return errors.Wrapf(err, "unable to marshal object to yaml: %v", object)
	}
	return f.Write(fileName, y)
}

// Read reads a secret form the filesystem
func (f *fileStore) Read(fileName string) ([]byte, error) {
	return ioutil.ReadFile(fileName)
}

// ReadObject reads an object from the filesystem as yaml
func (f *fileStore) ReadObject(fileName string, object interface{}) error {
	data, err := f.Read(fileName)
	if err != nil {
		return errors.Wrapf(err, "unable to read %s", fileName)
	}
	return yaml.Unmarshal(data, object)
}
