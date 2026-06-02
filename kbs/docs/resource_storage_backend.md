# Resource Storage Backend

KBS stores confidential resources through a `StorageBackend` abstraction specified
by a Rust trait. The `StorageBackend` interface can be implemented for different
storage backends like e.g. databases or local file systems.

The [KBS config file](./config.md)
defines which resource backend KBS will use. The default is the local
file system (`LocalFs`).

### Local File System Backend

With the local file system backend default implementation, each resource
file maps to a KBS resource URL. The file path to URL conversion scheme is
defined below:

| Resource File Path  | Resource URL |
| ------------------- | -------------- |
| `file://<$(KBS_REPOSITORY_DIR)>/<repository_name>/<type>/<tag>`  |  `https://<kbs_address>/kbs/v0/resource/<repository_name>/<type>/<tag>`  |

The KBS root file system resource path is specified in the KBS config file
as well, and the default value is `/opt/confidential-containers/kbs/repository`.

### Aliyun KMS

[Alibaba Cloud KMS](https://www.alibabacloud.com/en/product/kms?_p_lc=1)(a.k.a Aliyun KMS)
can also work as the KBS resource storage backend.
In this mode, resources will be stored with [generic secrets](https://www.alibabacloud.com/help/en/kms/user-guide/manage-and-use-generic-secrets?spm=a2c63.p38356.0.0.dc4d24f7s0ZuW7) in a [KMS instance](https://www.alibabacloud.com/help/en/kms/user-guide/kms-overview?spm=a2c63.p38356.0.0.4aacf9e6V7IQGW).
One KBS can be configured with a specified KMS instance in `repository_config` field of KBS launch config. For config, see the [document](./config.md#repository-configuration).
These materials can be found in KMS instance's [AAP](https://www.alibabacloud.com/help/en/kms/user-guide/manage-aaps?spm=a3c0i.23458820.2359477120.1.4fd96e9bmEFST4).
When being accessed, a resource URI of `kbs:///repo/type/tag` will be translated into the generic secret with name `tag`. Hinting that `repo/type` field will be ignored.

### AWS Secrets Manager

[AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
can also work as the KBS resource storage backend. Build KBS with the `aws`
feature flag enabled. Resources are stored as Secrets Manager secrets and
fetched via `GetSecretValue`.

A resource URI of `kbs:///repo/type/tag` is translated into the Secrets Manager
secret with `SecretId = tag`. The `repo/type` portion is ignored — match the
behavior of the Aliyun KMS backend. `tag` may be either a secret name or a full
secret ARN.

This backend is read-only. Writes and deletes return an error — provision and
rotate secrets via AWS APIs.

### Hashicorp Vault Backend

[Vault KV secrets engine backend](./vault_kv.md)
