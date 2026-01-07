# helm chart to deploy caweb
Needs a secret for the ca. Create secret befor deploying the helm chart.

## needed secret beforhand
```bash
kubectl create secret generic ca-secret \
  --from-file=ca.pem=/local-ca/ca.pem \
  --from-file=ca.key=/local-ca/ca.key \
  -n caweb
```

```bash
helm install caweb . -n caweb --create-namespace
```

```bash
helm upgrade caweb . -n caweb 
```

```bash
helm uninstall caweb -n caweb
```
