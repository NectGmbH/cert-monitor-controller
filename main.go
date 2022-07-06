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
	workerProcessCount = 2
)

var version string = "dev"

func main() {
	var (
		kubeconfig, listen, logLevel, masterURL string
		rescanInterval                          time.Duration
	)

	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&listen, "listen", ":3000", "Address to listen on for HTTP requests")
	flag.StringVar(&logLevel, "log-level", "info", "Log-level to use for output")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.DurationVar(&rescanInterval, "rescan-interval", time.Hour, "How often to re-scan existing secrets without events")
	flag.Parse()

	logrusLevel, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.WithError(err).Fatal("parsing given log-level")
	}
	logrus.SetLevel(logrusLevel)

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

	kubeInformerFactory := informers.NewSharedInformerFactory(kubeClient, rescanInterval)

	ctrl := newController(
		kubeClient,
		kubeInformerFactory.Core().V1().Secrets(),
		metricsHandler,
	)

	stopCh := make(chan struct{})
	defer close(stopCh)

	metricsHandler.AddHandler()
	go http.ListenAndServe(listen, nil)

	logrus.WithField("version", version).Info("cert-monitor-controller started")

	kubeInformerFactory.Start(stopCh)
	ctrl.Run(workerProcessCount, stopCh)
}
