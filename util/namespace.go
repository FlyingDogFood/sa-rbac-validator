package util

import (
	v1 "k8s.io/api/core/v1"
)

func NamespacesToStrings(namespaces []*v1.Namespace) []string {
	result := make([]string, len(namespaces))
	for index, namespace := range namespaces {
		result[index] = namespace.Name
	}
	return result
}
