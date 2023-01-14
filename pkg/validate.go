package pkg

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog"

	util "github.com/flyingdogfood/sa-rbac-validator/util"
	admissionv1 "k8s.io/api/admission/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	v1 "k8s.io/client-go/informers/core/v1"
	rbacInformersv1 "k8s.io/client-go/informers/rbac/v1"
	"k8s.io/client-go/kubernetes"
)

type SaRbacValidatorConfig struct {
	Logger                     zerolog.Logger
	Client                     kubernetes.Clientset
	ClusterRoleBindingInformer rbacInformersv1.ClusterRoleBindingInformer
	RoleBindingInformer        rbacInformersv1.RoleBindingInformer
	ClusterRoleInformer        rbacInformersv1.ClusterRoleInformer
	RoleInformer               rbacInformersv1.RoleInformer
	NamespaceInformer          v1.NamespaceInformer
	ServiceAccountJsonPointer  string
	SaNotFoundBehavior         int
}

const (
	Deny = iota
	Allow
)

func PraseNotFoundBehavior(behavior string) (int, error) {
	behaviorLower := strings.ToLower(behavior)
	if behaviorLower == "deny" {
		return Deny, nil
	}
	if behaviorLower == "allow" {
		return Allow, nil
	}
	return -1, errors.New("Faild to phrase behavior. Behavior: " + behavior + " invalid")
}

func Validate(request *admissionv1.AdmissionRequest, saRbacValidatorConfig SaRbacValidatorConfig) *admissionv1.AdmissionResponse {
	logger := saRbacValidatorConfig.Logger.With().Str("Request UID", string(request.UID)).Logger()
	logger.Info().Msg("Start Validating Request")
	//Extract user from reqeust to later compare it's permissions to the service acount
	user := util.ExtractUser(request)
	logger.Info().Str("UserName", user.GetName()).Str("UserUID", user.GetUID()).Strs("UserGroups", user.GetGroups())

	//Extract service account name from admission request
	serviceAccount, err := util.ExtractServiceAccount(request, saRbacValidatorConfig.ServiceAccountJsonPointer)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to extract ServiceAccount")
		if saRbacValidatorConfig.SaNotFoundBehavior == Deny {
			logger.Info().Msg("Request denied")
			return &admissionv1.AdmissionResponse{
				UID:     request.UID,
				Allowed: false,
				Result: &metav1.Status{
					Message: err.Error(),
					Code:    http.StatusForbidden,
				},
			}
		}
		logger.Info().Msg("Request allowed")
		return &admissionv1.AdmissionResponse{
			UID:     request.UID,
			Allowed: true,
			Result: &metav1.Status{
				Message: err.Error(),
				Code:    http.StatusOK,
			},
		}
	}
	logger.Info().Str("ServiceAccountName", serviceAccount)

	// Create the user.Info struct for the service account as we are using this to get all the associated roles of the serviceaccount
	serviceAccountUser, err := util.GetServiceAccount(&saRbacValidatorConfig.Client, serviceAccount, request.Namespace)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get ServiceAccount User")
		return &admissionv1.AdmissionResponse{
			UID:     request.UID,
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
				Code:    http.StatusForbidden,
			},
		}
	}
	logger.Info().Str("ServiceAccountName", serviceAccountUser.GetName()).Str("ServiceAccountNamespace", request.Namespace).Str("ServiceAccountUID", serviceAccountUser.GetUID()).Strs("ServiceAccountGroups", serviceAccountUser.GetGroups())

	namespaces, err := saRbacValidatorConfig.NamespaceInformer.Lister().List(labels.Everything())
	if err != nil {
		logger.Error().Err(err).Msg("Failed to list namespaces")
		return &admissionv1.AdmissionResponse{
			UID:     request.UID,
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
				Code:    http.StatusForbidden,
			},
		}
	}

	isEscalated := false
	namespacedEscalationRules := make(map[string][]rbacv1.PolicyRule)

	for _, namespace := range namespaces {
		logger.Info().Str("Processing Namespace", namespace.Name)
		var saRules []rbacv1.PolicyRule
		var userRules []rbacv1.PolicyRule
		roleBindings, err := saRbacValidatorConfig.RoleBindingInformer.Lister().RoleBindings(namespace.Name).List(labels.Everything())
		if err != nil {
			return &admissionv1.AdmissionResponse{
				UID:     request.UID,
				Allowed: false,
				Result: &metav1.Status{
					Message: err.Error(),
					Code:    http.StatusForbidden,
				},
			}
		}
		for _, roleBinding := range roleBindings {
			logger.Info().Str("Processing RoleBinding", roleBinding.Name)
			if util.SubjectsMatchesUserOrServiceAccount(roleBinding.Subjects, serviceAccountUser, roleBinding.Namespace) {
				rules, err := util.GetRulesForRoleBinding(*roleBinding, saRbacValidatorConfig.RoleInformer, saRbacValidatorConfig.ClusterRoleInformer)
				if err != nil {
					return &admissionv1.AdmissionResponse{
						UID:     request.UID,
						Allowed: false,
						Result: &metav1.Status{
							Message: err.Error(),
							Code:    http.StatusForbidden,
						},
					}
				}
				rules = util.ExtendRules(rules)
				saRules = util.AddRules(saRules, rules)
			}
			//TODO: Shortcut if there is no Rolebinding that matches SA in namespace
			if util.SubjectsMatchesUserOrServiceAccount(roleBinding.Subjects, user, roleBinding.Namespace) {
				rules, err := util.GetRulesForRoleBinding(*roleBinding, saRbacValidatorConfig.RoleInformer, saRbacValidatorConfig.ClusterRoleInformer)
				if err != nil {
					return &admissionv1.AdmissionResponse{
						UID:     request.UID,
						Allowed: false,
						Result: &metav1.Status{
							Message: err.Error(),
							Code:    http.StatusForbidden,
						},
					}
				}
				rules = util.ExtendRules(rules)
				saRules = util.AddRules(userRules, rules)
			}
		}
		escalationRules := util.IsRuleEscalation(userRules, saRules)
		if len(escalationRules) > 0 {
			isEscalated = true
			namespacedEscalationRules[namespace.Name] = util.IsRuleEscalation(userRules, saRules)
		}
	}

	var saRules []rbacv1.PolicyRule
	var userRules []rbacv1.PolicyRule
	clusterRoleBindings, err := saRbacValidatorConfig.ClusterRoleBindingInformer.Lister().List(labels.Everything())
	if err != nil {
		return &admissionv1.AdmissionResponse{
			UID:     request.UID,
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
				Code:    http.StatusForbidden,
			},
		}
	}
	for _, clusterRoleBinding := range clusterRoleBindings {
		if util.SubjectsMatchesUserOrServiceAccount(clusterRoleBinding.Subjects, serviceAccountUser, clusterRoleBinding.Namespace) {
			rules, err := util.GetRulesForClusterRoleBinding(*clusterRoleBinding, saRbacValidatorConfig.ClusterRoleInformer)
			if err != nil {
				return &admissionv1.AdmissionResponse{
					UID:     request.UID,
					Allowed: false,
					Result: &metav1.Status{
						Message: err.Error(),
						Code:    403,
					},
				}
			}
			rules = util.ExtendRules(rules)
			saRules = util.AddRules(saRules, rules)
		}
		//TODO: Shortcut if there is no Rolebinding that matches SA at cluster scope
		if util.SubjectsMatchesUserOrServiceAccount(clusterRoleBinding.Subjects, user, clusterRoleBinding.Namespace) {
			rules, err := util.GetRulesForClusterRoleBinding(*clusterRoleBinding, saRbacValidatorConfig.ClusterRoleInformer)
			if err != nil {
				return &admissionv1.AdmissionResponse{
					UID:     request.UID,
					Allowed: false,
					Result: &metav1.Status{
						Message: err.Error(),
						Code:    http.StatusForbidden,
					},
				}
			}
			rules = util.ExtendRules(rules)
			saRules = util.AddRules(userRules, rules)
		}
	}
	clusterEscalatedRules := util.IsRuleEscalation(userRules, saRules)
	if isEscalated {
		var errorString string
		if len(clusterEscalatedRules) > 0 {
			rulesString, err := util.RulesToString(clusterEscalatedRules)
			if err != nil {
				return &admissionv1.AdmissionResponse{
					UID:     request.UID,
					Allowed: false,
					Result: &metav1.Status{
						Message: err.Error(),
						Code:    http.StatusForbidden,
					},
				}
			}
			errorString = "Request try to grant permissions at Cluster-Scope that are currently not held by user: " + rulesString + "."
		}
		if isEscalated {
			for namespace, rules := range namespacedEscalationRules {
				rulesString, err := util.RulesToString(rules)
				if err != nil {
					return &admissionv1.AdmissionResponse{
						UID:     request.UID,
						Allowed: false,
						Result: &metav1.Status{
							Message: err.Error(),
							Code:    http.StatusForbidden,
						},
					}
				}
				errorString = errorString + "Request try to grant permissions in Namespace: " + namespace + " that are currently not held by user: " + rulesString + "."
			}
		}

		return &admissionv1.AdmissionResponse{
			UID:     request.UID,
			Allowed: false,
			Result: &metav1.Status{
				Message: errorString,
				Code:    http.StatusForbidden,
			},
		}
	}
	return &admissionv1.AdmissionResponse{
		UID:     request.UID,
		Allowed: true,
		Result: &metav1.Status{
			Message: "Request allowed",
			Code:    http.StatusOK,
		},
	}

}
