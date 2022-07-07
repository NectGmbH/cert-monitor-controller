package main

import (
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

var errIsNotCertificate = errors.New("key does not contain a certificate")

// scan is the primary logic iterating through the fields of a secret
// checking for the existence of a certificate within any of the keys
// adding the expiry to the prometheusHandler if found
func (c *controller) scan(qe *queueEntry) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(qe.key)
	if err != nil {
		return errors.Wrapf(err, "splitting key %q to namespace / name", qe.key)
	}

	if qe.reason == updateReasonDelete {
		// We cannot fetch a deleted secret anymore, handle it without fetching
		c.metricsHandler.RemoveCertExpiry(namespace, name)
		return nil
	}

	secret, err := c.secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return errors.Wrapf(err, "getting secret %q", qe.key)
	}

	for entry, data := range secret.Data {
		logger := logrus.WithFields(logrus.Fields{
			"entry":     entry,
			"name":      name,
			"namespace": namespace,
		})

		// Secret is updated or added, scan entries and add metric
		expiresIn, err := c.expiryFromData(data)
		if errors.Is(err, errIsNotCertificate) {
			// The key did not look like a cert, that's fine.
			logger.Debug("does not contain cert")
			continue
		}

		if err != nil {
			logger.WithError(err).Error("evaluating entry")
			continue
		}

		logger.WithField("expires_in", expiresIn).Debug("adding cert expiry")
		c.metricsHandler.SetCertExpiry(namespace, name, entry, expiresIn)
	}

	return nil
}

// expiryFromData takes the PEM encoded x509 certificate and extracts
// the time until expiration. The certificate is not valdiated!
func (c *controller) expiryFromData(data []byte) (time.Duration, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		// That was no PEM block, certs should be PEM blocks
		return 0, errIsNotCertificate
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, errors.Wrap(err, "parsing certificate")
	}

	return time.Until(cert.NotAfter), nil
}
