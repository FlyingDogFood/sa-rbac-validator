package util

import (
	rbacv1 "k8s.io/api/rbac/v1"
	rbacInformersv1 "k8s.io/client-go/informers/rbac/v1"
)

func GetRulesForClusterRoleBinding(clusterRoleBinding rbacv1.ClusterRoleBinding, clusterRoleInformer rbacInformersv1.ClusterRoleInformer) ([]rbacv1.PolicyRule, error) {
	clusterRole, err := clusterRoleInformer.Lister().Get(clusterRoleBinding.RoleRef.Name)
	return clusterRole.Rules, err
}
