## Création des configmap et secrets
```
kubectl create secret generic dlppkidev-secrets --from-file=ca.pem --from-file=ca-key.pem -n my-app
kubectl create configmap dlppkidev-config --from-file=dlp-pki-dev/deployment/dlppkidev.yml -n my-app
```

## Urls
[dashboard](http://192.168.56.10)

[gogs](http://192.168.56.10:8888)

[drone](http://192.168.56.10:8000)

[dlppkidev](http://192.168.56.10:8090)

[wrapper](http://192.168.56.10:8095)

[prometheus](http://192.168.56.12:30999)

## Tests

```
siege -t 5M -c 3 -d 0.5 http://192.168.56.10:8090/identity/myidentity
```


## Busybox


```
kubectl run busybox --image=my-docker-registry:5443/busybox --command -- sleep 3600
```
