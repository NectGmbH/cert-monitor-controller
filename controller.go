package main

import (
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	secrets "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type (
	controller struct {
		kubeClient     kubernetes.Interface
		metricsHandler *prometheusHandler

		secretLister  listers.SecretLister
		secretsSynced cache.InformerSynced

		queue workqueue.RateLimitingInterface
	}

	queueEntry struct {
		key    string
		reason string
	}
)

const (
	updateReasonAdd    = "add"
	updateReasonDelete = "delete"
	updateReasonUpdate = "update"
)

func newController(
	kubeClient kubernetes.Interface,
	informer informers.SecretInformer,
	metricsHandler *prometheusHandler,
) *controller {
	c := &controller{
		kubeClient:     kubeClient,
		metricsHandler: metricsHandler,
		queue:          workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "secret"),
	}

	informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.enqueue(obj, updateReasonAdd) },
		DeleteFunc: func(obj any) { c.enqueue(obj, updateReasonDelete) },
		UpdateFunc: func(_, obj any) { c.enqueue(obj, updateReasonUpdate) },
	})

	c.secretLister = informer.Lister()
	c.secretsSynced = informer.Informer().HasSynced

	return c
}

func (c *controller) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	logrus.Info("starting cert-monitor controller")
	defer logrus.Info("shutting down cert-monitor controller")

	if !cache.WaitForCacheSync(stopCh, c.secretsSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *controller) enqueue(obj any, reason string) {
	if _, ok := obj.(*secrets.Secret); !ok {
		// Sanity-check, this should not happen but we check this nevertheless
		utilruntime.HandleError(errors.New("object received was not core/v1.Secret"))
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(errors.Wrap(err, "getting key for object")) // We don't log the object for security reasons: It's a secret!
		return
	}

	logrus.WithFields(logrus.Fields{
		"key":    key,
		"reason": reason,
	}).Info("enqueing secret for scan")
	c.queue.Add(&queueEntry{key: key, reason: reason})
}

func (c *controller) processNextWorkItem() bool {
	qei, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(qei)

	qe, ok := qei.(*queueEntry)
	if !ok {
		// However this happened: Queue did not contain valid entry
		utilruntime.HandleError(errors.Errorf("queue entry had wrong type %t", qei))
		return true
	}

	if err := c.scan(qe); err != nil {
		c.queue.AddRateLimited(qei)
		utilruntime.HandleError(errors.Wrapf(err, "scan for %q failed", qe))

		return true
	}

	c.queue.Forget(qei)
	return true
}

func (c *controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (q queueEntry) String() string {
	return strings.Join([]string{q.reason, q.key}, "::")
}
