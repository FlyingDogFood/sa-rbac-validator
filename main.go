package main

import (
	"encoding/json"
	"net/http"
	"os"

	pkg "github.com/flyingdogfood/sa-rbac-validator/pkg"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type validatingWebhook struct {
	saRbacValidatorConfig pkg.SaRbacValidatorConfig
}

func (v *validatingWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var review admissionv1.AdmissionReview

	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	review.Response = pkg.Validate(review.Request, v.saRbacValidatorConfig)

	responseBytes, err := json.Marshal(review)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		//TODO
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		//TODO
	}

	stopper := make(chan struct{})
	defer close(stopper)

	factory := informers.NewSharedInformerFactory(client, 0)
	clusterRoleBindingInformer := factory.Rbac().V1().ClusterRoleBindings()
	roleBindingInformer := factory.Rbac().V1().RoleBindings()
	clusterRoleInformer := factory.Rbac().V1().ClusterRoles()
	roleInformer := factory.Rbac().V1().Roles()
	namespaceInformer := factory.Core().V1().Namespaces()

	clusterRoleBindingInformer.Informer()
	roleBindingInformer.Informer()
	clusterRoleInformer.Informer()
	roleInformer.Informer()
	namespaceInformer.Informer()

	factory.Start(stopper)
	factory.WaitForCacheSync(stopper)

	http.Handle("/validate", &validatingWebhook{
		saRbacValidatorConfig: pkg.SaRbacValidatorConfig{
			Client:                     *client,
			ClusterRoleBindingInformer: clusterRoleBindingInformer,
			RoleBindingInformer:        roleBindingInformer,
			ClusterRoleInformer:        clusterRoleInformer,
			RoleInformer:               roleInformer,
			NamespaceInformer:          namespaceInformer,
			ServiceAccountJsonPointer:  os.Getenv("SA_RBAC_VALIDATOR_SA_JSONPATH"),
		},
	})
	http.ListenAndServeTLS(":8443", os.Getenv("SA_RBAC_VALIDATOR_TLS_CRT"), os.Getenv("SA_RBAC_VALIDATOR_TLS_KEY"), nil)
}
