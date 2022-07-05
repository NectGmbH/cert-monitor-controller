package main

import (
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type (
	prometheusHandler struct {
		expiresInDaysMetric *prometheus.GaugeVec
	}
)

func newPrometheusHandler() (*prometheusHandler, error) {
	expiresInDaysMetric := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Help:      "Number of hours the certificate will expire in",
			Name:      "expires_in",
			Namespace: "k8s_cert_monitor",
		},
		[]string{"namespace", "name", "key"},
	)

	if err := prometheus.Register(expiresInDaysMetric); err != nil {
		return nil, errors.Wrap(err, "registering expires_in metric")
	}

	return &prometheusHandler{
		expiresInDaysMetric: expiresInDaysMetric,
	}, nil
}

func (p prometheusHandler) AddHandler() {
	http.Handle("/metrics", promhttp.Handler())
}

func (p prometheusHandler) RemoveCertExpiry(namespace, name, key string) bool {
	return p.expiresInDaysMetric.Delete(prometheus.Labels{
		"namespace": namespace,
		"name":      name,
		"key":       key,
	})
}

func (p prometheusHandler) SetCertExpiry(namespace, name, key string, expiresIn time.Duration) {
	p.expiresInDaysMetric.With(prometheus.Labels{
		"namespace": namespace,
		"name":      name,
		"key":       key,
	}).Set(float64(expiresIn / time.Hour))
}
