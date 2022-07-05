package main

import (
	"flag"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	resyncDuration     = 30 * time.Second // TODO: Is 30s resync needed?
	workerProcessCount = 2
)

var version string = "dev"

func main() {
	var kubeconfig, listen, masterURL string

	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&listen, "listen", ":3000", "Address to listen on for HTTP requests")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.Parse()

	metricsHandler, err := newPrometheusHandler()
	if err != nil {
		logrus.WithError(err).Fatal("initializing prometheus metrics")
	}

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		logrus.WithError(err).Fatal("building kubeconfig")
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logrus.WithError(err).Fatal("building kubernetes clientset")
	}

	kubeInformerFactory := informers.NewSharedInformerFactory(kubeClient, resyncDuration)

	ctrl := newController(
		kubeClient,
		kubeInformerFactory.Core().V1().Secrets(),
		metricsHandler,
	)

	stopCh := make(chan struct{})
	defer close(stopCh)

	go http.ListenAndServe(listen, nil)

	logrus.WithField("version", version).Info("cert-monitor-controller started")

	kubeInformerFactory.Start(stopCh)
	ctrl.Run(workerProcessCount, stopCh)
}
