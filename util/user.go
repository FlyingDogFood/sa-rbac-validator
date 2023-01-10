package util

import (
	"context"

	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"
	rbacinformersv1 "k8s.io/client-go/informers/rbac/v1"
	"k8s.io/client-go/kubernetes"
)

func GetServiceAccount(client kubernetes.Interface, name string, namespace string) (user.Info, error) {
	serviceAccount, err := client.CoreV1().ServiceAccounts(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	token, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), serviceAccount.Secrets[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	review := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: string(token.Data["token"]),
		},
	}

	// send the TokenReview request
	result, err := client.AuthenticationV1().TokenReviews().Create(context.TODO(), review, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	var user user.Info = &user.DefaultInfo{
		Name:   name,
		UID:    result.Status.User.UID,
		Groups: result.Status.User.Groups,
	}

	return user, nil
}

func SubjectsMatchesUserOrServiceAccount(subjects []rbacv1.Subject, user user.Info, namespace string) bool {
	for _, subject := range subjects {
		if SubjectMatchesUserOrServiceAccount(subject, user, namespace) {
			return true
		}
	}
	return false
}

func SubjectMatchesUserOrServiceAccount(subject rbacv1.Subject, user user.Info, namespace string) bool {
	if subject.Kind == "User" && subject.Name == user.GetName() {
		return true
	}
	if subject.Kind == "ServiceAccount" && subject.Name == user.GetName() && subject.Namespace == namespace {
		return true
	}
	if subject.Kind == "Group" {
		for _, group := range user.GetGroups() {
			if subject.Name == group {
				return true
			}
		}
	}
	return false
}

func GetRolesForUser(user user.Info, roleBindingInformer rbacinformersv1.RoleBindingInformer, roleInformer rbacinformersv1.RoleInformer) ([]rbacv1.Role, error) {
	var roles []rbacv1.Role
	roleBindings, err := roleBindingInformer.Lister().List(labels.Everything())
	if err != nil {
		return nil, err
	}
	for _, roleBinding := range roleBindings {
		if SubjectsMatchesUserOrServiceAccount(roleBinding.Subjects, user, roleBinding.Namespace) {
			roles = append(roles)
		}
	}
	return roles, nil
}
