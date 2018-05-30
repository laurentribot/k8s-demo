## Création des configmap et secrets
```
kubectl create secret generic dlppkidev-secrets --from-file=ca.pem --from-file=ca-key.pem
kubectl create configmap dlppkidev-config --from-file=dlp-pki-dev/deployment/dlppkidev.yml
```

## Urls
[dashboard](http://192.168.56.10)

[gogs](http://192.168.56.10:8080)

[drone](http://192.168.56.10:8888)

[dlppkidev](http://192.168.56.10:8090)

https://docs.bitnami.com/kubernetes/how-to/configure-autoscaling-custom-metrics/