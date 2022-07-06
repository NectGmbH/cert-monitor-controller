package main

import (
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

var errIsNotCertificate = errors.New("key does not contain a certificate")

func (c *controller) scan(qe *queueEntry) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(qe.key)
	if err != nil {
		return errors.Wrapf(err, "splitting key %q to namespace / name", qe.key)
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

		if qe.reason == updateReasonDelete {
			// The secret is to be deleted, remove its metrics
			logger.Debug("removing metric")
			c.metricsHandler.RemoveCertExpiry(namespace, name, entry)
			continue
		}

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

func (c *controller) expiryFromData(data []byte) (time.Duration, error) {
	plain := make([]byte, base64.StdEncoding.DecodedLen(len(data)))

	_, err := base64.StdEncoding.Decode(plain, data)
	if err != nil {
		return 0, errors.Wrap(err, "base64 decoding data")
	}

	cert, err := x509.ParseCertificate(plain)
	if err != nil {
		return 0, errors.Wrap(err, "parsing certificate")
	}

	return time.Until(cert.NotAfter), nil
}
