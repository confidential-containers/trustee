# Deploy Key Broker Service on Kubernetes

We will see how to deploy KBS (with builtin Attestation Service) on a Kubernetes cluster.

## The secrets

Create a secret that you want to be served using this instance of KBS:

```bash
echo "This is my super secert" > overlays/key.bin
```

If you have more than one secret, copy them over to the `config/kubernetes/overlays` directory and add those to the `overlays/kustomization.yaml` file after as shown below:

```yaml
...
- name: keys
  files:
  - key.bin
  - secret.key
  - passowrd.txt
  ...
```

## Defining KBS repositories

With the default configuration the keys will be stored in `reponame/workload_key/`. If you wish to define a different repository make necessary changes to the `overlays/patch.yaml` file.

## Optional: Expose KBS using Ingress

If you would like to expose KBS using Ingress, then run the following commands:

> [!NOTE]
> If you are using AKS then set the `KBS_INGRESS_CLASS` to `addon-http-application-routing` and get the `CLUSTER_SPECIFIC_DNS_ZONE` by following the instructions [here](https://learn.microsoft.com/en-us/azure/aks/http-application-routing#enable-http-application-routing).

```bash
export KBS_INGRESS_CLASS="REPLACE_ME"
export CLUSTER_SPECIFIC_DNS_ZONE="REPLACE_ME"
export KBS_INGRESS_HOST="kbs.${CLUSTER_SPECIFIC_DNS_ZONE}"

pushd overlays
envsubst <ingress.yaml >ingress.yaml.tmp && mv ingress.yaml.tmp ingress.yaml
kustomize edit add resource ingress.yaml
popd
```

## Deploy KBS

Deploy KBS by running the following command:

```bash
./deploy-kbs.sh
```

## Check deployment

Run the following command to check if the KBS is deployed successfully:

```bash
kubectl -n coco-tenant get pods
```

A successful run will look like the following:

```console
$ kubectl -n coco-tenant get pods
NAME                  READY   STATUS    RESTARTS   AGE
kbs-bdffc8dd4-jv2kr   1/1     Running   0          7m30s
```

A Kuberentes service is also deployed as a part of this deployment, you can reach the KBS:

```console
$ kubectl -n coco-tenant get service
NAME   TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE
kbs    ClusterIP   10.0.210.190   <none>        8080/TCP   4s
```
