package main

import (
	"net/http"
	"path"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type (
	prometheusHandler struct {
		expiresInDaysMetric *prometheus.GaugeVec

		keyRegistry map[string][]string
		lock        sync.RWMutex
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
		keyRegistry:         make(map[string][]string),
	}, nil
}

func (p *prometheusHandler) AddHandler() {
	http.Handle("/metrics", promhttp.Handler())
}

func (p *prometheusHandler) RemoveCertExpiry(namespace, name string) {
	for _, key := range p.getKeys(namespace, name) {
		p.expiresInDaysMetric.Delete(prometheus.Labels{
			"namespace": namespace,
			"name":      name,
			"key":       key,
		})
	}

	p.clearKeys(namespace, name)
}

func (p *prometheusHandler) SetCertExpiry(namespace, name, key string, expiresIn time.Duration) {
	p.expiresInDaysMetric.With(prometheus.Labels{
		"namespace": namespace,
		"name":      name,
		"key":       key,
	}).Set(float64(expiresIn) / float64(time.Hour))

	p.registerKey(namespace, name, key)
}

func (p *prometheusHandler) clearKeys(namespace, name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.keyRegistry, path.Join(namespace, name))
}

func (p *prometheusHandler) getKeys(namespace, name string) []string {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.keyRegistry[path.Join(namespace, name)]
}

func (p *prometheusHandler) registerKey(namespace, name, key string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	for _, k := range p.keyRegistry[path.Join(namespace, name)] {
		if k == key {
			return
		}
	}

	p.keyRegistry[path.Join(namespace, name)] = append(
		p.keyRegistry[path.Join(namespace, name)],
		key,
	)
}
