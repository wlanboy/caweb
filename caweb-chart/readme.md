## create secret
```bash
kubectl create secret generic ca-secret \
  --from-file=ca.pem=/local-ca/ca.pem \
  --from-file=ca.key=/local-ca/ca.key \
  -n caweb
```