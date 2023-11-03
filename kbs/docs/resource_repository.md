# Resource Repository

KBS stores confidential resources through a `Repository` abstraction specified
by a Rust trait. The `Repository` interface can be implemented for different
storage backends like e.g. databases or local file systems.

The [KBS config file](./config.md)
defines which resource repository backend KBS will use. The default is the local
file system (`LocalFs`).

### Local File System Repository

With the local file system `Repository` default implementation, each resource
file maps to a KBS resource URL. The file path to URL conversion scheme is
defined below:

| Resource File Path  | Resource URL |
| ------------------- | -------------- |
| `file://<$(KBS_REPOSITORY_DIR)>/<repository_name>/<type>/<tag>`  |  `https://<kbs_address>/kbs/v0/resource/<repository_name>/<type>/<tag>`  |

The KBS root file system resource path is specified in the KBS config file
as well, and the default value is `/opt/confidential-containers/kbs/repository`.