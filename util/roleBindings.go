package util

import (
	rbacv1 "k8s.io/api/rbac/v1"
	rbacInformersv1 "k8s.io/client-go/informers/rbac/v1"
)

func GetRulesForRoleBinding(roleBinding rbacv1.RoleBinding, roleInformer rbacInformersv1.RoleInformer, clusterRoleInformer rbacInformersv1.ClusterRoleInformer) ([]rbacv1.PolicyRule, error) {
	if roleBinding.RoleRef.Kind == "Role" {
		role, err := roleInformer.Lister().Roles(roleBinding.Namespace).Get(roleBinding.RoleRef.Name)
		return role.Rules, err
	}
	clusterRole, err := clusterRoleInformer.Lister().Get(roleBinding.RoleRef.Name)
	return clusterRole.Rules, err
}
