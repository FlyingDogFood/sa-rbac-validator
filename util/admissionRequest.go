package util

import (
	"errors"
	"reflect"

	"k8s.io/apiserver/pkg/authentication/user"

	jsonpointer "github.com/go-openapi/jsonpointer"
	admissionv1 "k8s.io/api/admission/v1"
)

func ExtractUser(request *admissionv1.AdmissionRequest) user.Info {
	var user user.Info = &user.DefaultInfo{
		Name:   request.UserInfo.Username,
		UID:    request.UserInfo.UID,
		Groups: request.UserInfo.Groups,
	}

	return user
}

func ExtractServiceAccount(request *admissionv1.AdmissionRequest, jsonPointer string) (string, error) {
	ptr, err := jsonpointer.New(jsonPointer)
	if err != nil {
		return "", err
	}
	val, kind, err := ptr.Get(request.Object)
	if err != nil {
		return "", err
	}
	if kind != reflect.String {
		return "", errors.New("Expected string but got " + kind.String() + " for jsonPointer: " + jsonPointer)
	}
	return val.(string), nil
}
