# Key Broker Service

The Confidential Containers Key Broker Service (KBS) is a remote attestation
entry point, also known as a [Relying Party](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html)
in [RATS](https://datatracker.ietf.org/doc/draft-ietf-rats-architecture/)
role terminology.

## Protocol

The KBS implements and supports a simple, vendor and hardware-agnostic
[implementation protocol](https://github.com/confidential-containers/kbs/blob/main/docs/kbs_attestation_protocol.md).
