# Deploy Key Broker Service on Kubernetes

We will see how to deploy KBS (with builtin Attestation Service) on a Kubernetes cluster.

> :warning: **Be aware that the manifests and instructions below do not account for all stateful resources in a KBS deployment.** Changes to a deployment may be lost if the pod is restarted or rescheduled and service replication might yield inconsistent behaviour. For a production deployment, consider using a persistent volume.

## The secrets

Create a secret that you want to be served using this instance of KBS:

```bash
echo "This is my super secret" > overlays/key.bin
```
or, if deploying on IBM Secure Execution run:
```bash
echo "This is my super secret" > overlays/ibm-se/key.bin
```

If you have more than one secret, copy them over to the `config/kubernetes/overlays` directory and add those to the `overlays/kustomization.yaml` file after as shown below:

```yaml
...
- name: keys
  files:
  - key.bin
  - secret.key
  - password.txt
  ...
```

## Defining KBS repositories

With the default configuration the keys will be stored in `reponame/workload_key/`. If you wish to define a different repository make necessary changes to the `overlays/patch.yaml` file.

## Optional: Changing default policies

The default deployed resources policy file is `base/policy.rego`. If you wish to change the default then edit that file. For example, suppose that you want to have the "allow all" policy applied, do:

```bash
cp ../../sample_policies/allow_all.rego base/policy.rego
```

## Optional: Expose KBS using Ingress

If you would like to expose KBS using Ingress, then run the following commands:

```bash
export KBS_INGRESS_CLASS="REPLACE_ME"
export CLUSTER_SPECIFIC_DNS_ZONE="REPLACE_ME"
export KBS_INGRESS_HOST="kbs.${CLUSTER_SPECIFIC_DNS_ZONE}"

pushd overlays
envsubst <ingress.yaml >ingress.yaml.tmp && mv ingress.yaml.tmp ingress.yaml
kustomize edit add resource ingress.yaml
popd
```

If you are using AKS then one option is to enable the **approuting** add-on in your cluster (more information [here](https://learn.microsoft.com/en-us/azure/aks/app-routing)) and set the above environment variables as:
* `KBS_INGRESS_CLASS="webapprouting.kubernetes.azure.com"`
* the **approuting** add-on doesn't create a managed cluster DNS zone, so you will need to create it yourself and attach to **approuting** (more information [here](https://learn.microsoft.com/en-us/azure/aks/app-routing-dns-ssl#create-a-public-azure-dns-zone)). Then set `CLUSTER_SPECIFIC_DNS_ZONE` to the created zone name
* in case you don't want a cluster DNS zone, export `KBS_INGRESS_HOST="\"\""` and use the ingress public IP:
  ```bash
  kubectl get service -n app-routing-system nginx -o jsonpath="{.status.loadBalancer.ingress[0].ip}"
  ```

## Optional: Use non-release images

Sometimes it may be desirable to deploy KBS with an image that is not what is set in the repo (typically
the latest release image). To change the deployment to use a staging build, set the image using `kustomize`:

```bash
pushd base
kustomize edit set image kbs-container-image=ghcr.io/confidential-containers/staged-images/kbs:65ee7e1acccd13dcb515058e71c5f8bfb4281e35
popd
```

The available image tags can be found in the [CoCo packages listing](https://github.com/orgs/confidential-containers/packages?repo_name=trustee).

## Optional: Expose KBS using Nodeport

If you would like to expose KBS service using Nodeport then export the following environment variable:

```bash
export DEPLOYMENT_DIR=nodeport
```

Once you deploy the KBS, you can use the services' nodeport and the Kubernetes node's IP to reach out to the KBS. You can generate the KBS URL by running the following command:

```bash
echo $(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}'):$(kubectl get svc kbs -n coco-tenant -o jsonpath='{.spec.ports[0].nodePort}')
```

## Optional: Use custom Intel DCAP configuration

If you would like to override the default `sgx_default_qcnl.conf` in the KBS/AS images, copy/configure one into `custom_pccs/` directory and deploy using:

```bash
export DEPLOYMENT_DIR=custom_pccs
```

NB: this currently builds on `nodeport` kustomization.

## Deploy KBS

Deploy KBS by running the following command:

```bash
./deploy-kbs.sh
```

When deploying trustee on an [IBM Secure Execution](https://www.ibm.com/docs/en/linux-on-systems?topic=management-secure-execution)
enabled environment, where the IBM SE verifier verifier is needed,
an environment variable `IBM_SE_CREDS_DIR` is needed that points to a directory containing extra files required for
attestation on IBM Secure Execution:

```
$ export IBM_SE_CREDS_DIR=/path/to/your/directory
$ tree $IBM_SE_CREDS_DIR
/path/to/your/directory
├── certs
│   ├── DigiCertCA.crt
│   └── ibm-z-host-key-signing-gen2.crt
├── crls
│   └── ibm-z-host-key-gen2.crl
├── hdr
│   └── hdr.bin
├── hkds
│   └── HKD-3931-0275D38.crt
└── rsa
    ├── encrypt_key.pem
    └── encrypt_key.pub
5 directories, 7 files
```

Please check out the [documentation](https://github.com/confidential-containers/trustee/tree/main/deps/verifier/src/se) for details.

> [!NOTE]
> For running trustee on non-TEE s390x environment using the sample verifier for non-production environments, this extra
> `IBM_SE_CREDS_DIR` environment variable is not required.

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

## Delete KBS

```bash
$ kubectl delete -k ${DEPLOYMENT_DIR}/
```
or, if running on IBM Secure Execution run:
```bash
$ kubectl delete -k ${DEPLOYMENT_DIR}/ibm-se/ && kubectl delete pv test-local-pv
```
