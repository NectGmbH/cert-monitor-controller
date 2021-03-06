# cert-monitor-controller

Kubernetes controller to monitor certificates in secrets. Secrets are automatically scanned periodically and on add / update and expiry of contained certificates are exposed as Prometheus metrics.

The helm chart contains all resources to install the controller itself, PrometheusRule, ServiceMonitor and Grafana dashboard for the kube-prometheus-stack.

## Usage

```
Usage of ./cert-monitor-controller:
  -kubeconfig string
    	Path to a kubeconfig. Only required if out-of-cluster.
  -listen string
    	Address to listen on for HTTP requests (default ":3000")
  -log-level string
    	Log-level to use for output (default "info")
  -master string
    	The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.
  -metrics-prefix string
    	How to prefix the metrics generated by this controller (default "k8s_cert_monitor")
  -rescan-interval duration
    	How often to re-scan existing secrets without events (default 1h0m0s)
```

## Deploy using helm

```console
# helm upgrade -i certmon --namespace certmon ./chart -f my-values.yaml
```

For documentation of values available to override see [`chart/values.yaml`](./chart/values.yaml) file.
