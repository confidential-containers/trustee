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

### Pkcs11

The Pkcs11 backend uses Pkcs11 to store plaintext resources
in an HSM.
Pkcs11 is a broad specification supporting many cryptographic operations.
Here we make use only of a small subset of these features.
Often with Pkcs11 an HSM is used to wrap and unwrap keys or store wrapped keys.
Here we do something simpler. Since the KBS expects resources to be
in plaintext, we store these resources in the HSM as secret keys
of the generic secret type.
This storage backend will provision resource to the HSM
in the expected way when a user uploads a resource to the KBS.
The user must simply specify the location of an initialized HSM slot.
Keys can also be provisioned to the HSM separately
but they must have the expectd attributes.

The Pkcs11 backend is configured with the following values.

* `module` The module path should point to a binary implementing Pkcs11 for the HSM
	   that you want to use. For example, if you are using `SoftHSM`, you might
	   set the module path to `/usr/local/lib/softhsm/libsofthsm2.so`. 
* `slot_index` The slot index points to the slot in your HSM where the secrets will be stored.
               The slot must be initialized before starting the KBS.
	       No `slot_index` is set, the first slot will be used.
* `pin` The user password for authenticating a session with the above slot.
