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
	// prometheusHandler is a wrapper around a Prometheus GaugeVec
	prometheusHandler struct {
		expiresInDaysMetric *prometheus.GaugeVec

		keyRegistry map[string][]string
		lock        sync.RWMutex
	}
)

func newPrometheusHandler(metricsPrefix string) (*prometheusHandler, error) {
	expiresInDaysMetric := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Help:      "Number of hours the certificate will expire in",
			Name:      "expires_in",
			Namespace: metricsPrefix,
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

// AddHandler installs the HTTP listener in the default HTTP mux
func (p *prometheusHandler) AddHandler() {
	http.Handle("/metrics", promhttp.Handler())
}

// RemoveCertExpiry removes all metrics belonging to the given secret in given namespace
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

// SetCertExpiry adds or updates the expiry for the given key in namespace/name combination
func (p *prometheusHandler) SetCertExpiry(namespace, name, key string, expiresIn time.Duration) {
	p.expiresInDaysMetric.With(prometheus.Labels{
		"namespace": namespace,
		"name":      name,
		"key":       key,
	}).Set(float64(expiresIn) / float64(time.Hour))

	p.registerKey(namespace, name, key)
}

// clearKeys removes the keys for the given secret namespace/name
func (p *prometheusHandler) clearKeys(namespace, name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.keyRegistry, path.Join(namespace, name))
}

// getKeys returns the known keys within the secret in namespace/name combination
func (p *prometheusHandler) getKeys(namespace, name string) []string {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.keyRegistry[path.Join(namespace, name)]
}

// registerKey registers a new key for the given secret in namespace/name combination for later removal of the metric
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
