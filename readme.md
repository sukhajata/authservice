Provides authentication utilities such as creating users and getting and checking JWT tokens.

Requires a [keycloak](https://www.keycloak.org/) instance to be installed.

To build and push Docker image:
```shell script
docker build -t <your_username>/your-private-repo .
docker push <your_username>/your-private-repo
```

To deploy on Kubernetes, edit [values.yaml](./deployments/authservice-helm/values.yaml) then:
```shell script
helm upgrade --install \
    -f deployments/authservice-helm/values.yaml \
    authservice \
    authservice-helm
```

