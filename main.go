package main

import (
	"encoding/json"
	"net/http"
	"os"

	pkg "github.com/flyingdogfood/sa-rbac-validator/pkg"
	"github.com/rs/zerolog"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type validatingWebhook struct {
	saRbacValidatorConfig pkg.SaRbacValidatorConfig
}

func (v *validatingWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var review admissionv1.AdmissionReview

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		v.saRbacValidatorConfig.Logger.Error().Err(err).Msg("Failed to decode incoming AdmissionReview")
		w.WriteHeader(http.StatusBadRequest)
		review.Response = &admissionv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			},
		}
		responseBytes, err := json.Marshal(review)
		if err != nil {
			v.saRbacValidatorConfig.Logger.Error().Err(err).Msg("Failed to Marshall ErrorResponse")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(responseBytes)
		return
	}

	review.Response = pkg.Validate(review.Request, v.saRbacValidatorConfig)

	responseBytes, err := json.Marshal(review)
	if err != nil {
		v.saRbacValidatorConfig.Logger.Error().Err(err).Msg("Failed to Marshall Response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}

func main() {
	logger := zerolog.New(os.Stderr).Level(zerolog.InfoLevel)
	logLevelEnv := os.Getenv("SA_RBAC_VALIDATOR_LOG_LEVEL")
	logLevel, err := zerolog.ParseLevel(logLevelEnv)
	if err != nil || logLevel == zerolog.NoLevel {
		logLevel = zerolog.InfoLevel
		logger.Error().Err(err).Msg("Loglevel invalid defaulting to Info")
	}
	logger = zerolog.New(os.Stderr).Level(logLevel).With().Timestamp().Caller().Logger()

	logger.Info().Msg("Reading Cluster Config")
	config, err := rest.InClusterConfig()
	if err != nil {
		logger.Fatal().Err(err).Msg("Error getting kubernetes client config")
	}
	logger.Info().Msg("Creating kubernetes client")
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error creating kubernetes client")
	}

	stopper := make(chan struct{})
	defer close(stopper)

	logger.Info().Msg("Creating Informers")
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

	logger.Info().Msg("Start Informers")
	factory.Start(stopper)
	logger.Info().Msg("Waiting for informer caches")
	factory.WaitForCacheSync(stopper)

	saNotFoundBehavior, err := pkg.PraseNotFoundBehavior(os.Getenv("SA_RBAC_VALIDATOR_SA_NOT_FOUND_BEHAVIOR"))
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to phrase SA_RBAC_VALIDATOR_SA_NOT_FOUND_BEHAVIOR")
	}

	logger.Info().Msg("Add validate endpoint")
	http.Handle("/validate", &validatingWebhook{
		saRbacValidatorConfig: pkg.SaRbacValidatorConfig{
			Logger:                     logger,
			Client:                     *client,
			ClusterRoleBindingInformer: clusterRoleBindingInformer,
			RoleBindingInformer:        roleBindingInformer,
			ClusterRoleInformer:        clusterRoleInformer,
			RoleInformer:               roleInformer,
			NamespaceInformer:          namespaceInformer,
			ServiceAccountJsonPointer:  os.Getenv("SA_RBAC_VALIDATOR_SA_JSONPATH"),
			SaNotFoundBehavior:         saNotFoundBehavior,
		},
	})

	logger.Info().Msg("Start http listener")
	err = http.ListenAndServeTLS(":8443", "/var/run/secrets/certs/tls.crt", "/var/run/secrets/certs/tls.key", nil)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error creating http listener")
	}
}
