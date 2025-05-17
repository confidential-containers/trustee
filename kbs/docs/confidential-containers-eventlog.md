# Specification for Attestation Agent Event Log

## Introduction

The Attestation Agent Eventlog ([AAEL](https://github.com/confidential-containers/guest-components/issues/495)) are introduced to address limitations in existing logging frameworks such as [Confidential Computing Eventlog (CCEL)](https://uefi.org/specs/UEFI/2.10/38_Confidential_Computing.html), which primarily focus on capturing events during OS boot-up. Unlike CCEL, AAEL provides a comprehensive format for logging events that occur within Confidential VMs (CVMs) after the operating system has started. These VMs provide a highly secure and isolated environment crucial for protecting sensitive operations. The AAEL standard ensures that these post-OS events, which can include memory operations, network transactions, filesystem operations and container-related activities, etc, are coherently bound to hardware dynamic measurement registers, tying activities within the Confidential VMs to their secure hardware roots. This enables high integrity and verifiability for operations, greatly enhancing the ability to audit, troubleshoot, and respond to security incidents in confidential computing scenarios occurring post OS startup.

## Architecture

The architecture supporting AAEL seamlessly integrates with existing confidential computing systems,
providing a robust event logging and verification framework above the kernel level within CVMs. The [Attestation Agent (AA)](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent) is integral to this process, recording events within the AAEL framework and securely binding logs to hardware dynamic measurement registers.

It receives logging requests from system components.

These callers record events following the spec-defined AAEL Event, ensuring consistency and reliability in log data.

The [Attestation Service (AS)](https://github.com/confidential-containers/trustee/tree/main/attestation-service) offers a flexible platform for processing AAEL logs in a generalized manner, ensuring compatibility with various confidential computing environments for diverse event verification.
Furthermore, AS can conduct detailed analysis and enforce policies for AAEL events, utilizing the AAEL Event Spec for precise validation and scrutiny. This capability supports the development and execution of advanced security policies, enhancing the effectiveness and security of the VM.

```                                                                         
                                                                    
┌─────────────────────────────────────┐                             
│                                     │                             
│          ┌────────────────┐         │                             
│          │System Component│         │                             
│          └───────┬────────┘         │                             
│                  │                  │                             
│                  │                  │                             
│                  │                  │                             
│       ┌──────────▼──────────┐       │      ┌─────────────────────┐
│       │                     │       │      │                     │
│       │  Attestation Agent  ├───────┼─────►│ Attestation Service │
│       │                     │       │      │                     │
│       └───┬─────────┬───────┘       │      └─────────────────────┘
│           │         │               │                             
│           │         ▼               │                             
│    Extend │     ┌──────┐            │                             
│           │     │ AAEL │            │                             
│           │     └──────┘            │                             
│     ┌─────▼───────────────────┐     │                             
│     │ Runtime Measurements/PCR│     │                             
│     └─────────────────────────┘     │                             
│                                     │                             
│           Confidential VM           │                             
└─────────────────────────────────────┘                               
```

In this specification, we provide detailed information on the Attestation Agent Event Log (AAEL) format in confidential computing scenarios.

Currently, as the kernel does not offer a unified interface for maintaining Eventlogs [1], we have decided to temporarily use the AAEL. 

Once the kernel releases a unified Eventlog format, we will update the next version of the specification to ensure that the existing AAEL Event Entries are compatible with the new Kernel Eventlog format. We will also strive to minimize any impact on the user experience for existing users.

## Specifications

AAEL is a standard for event logging over guest kernel level.

### Attestation Agent Event Log (AAEL)

1. Binding of AAEL with Dynamic Measurement Registers

Entries recorded by AAEL are bound to a specific PCR register value. With each new event added, an extend operation is
performed on the designated PCR register. When the platform provides a (v)TPM interface, the PCR register corresponds
to the (v)TPM's PCR register. On a platform that is solely TEE, PCR is mapped to a specific [Confidential Computing event log Measurement Register (CCMR)](https://uefi.org/specs/UEFI/2.10/38_Confidential_Computing.html#virtual-platform-cc-event-log)
according to platform-specific rules. This mapping ensures AAEL has applicability even outside TEE scenarios.

2. AAEL Log Entry Format

AAEL log entries consist of two types: Event Entry and INIT Entry. 

__INIT Entry__ is recorded only once at the beginning of AAEL when AA first initializes, capturing the current value of a specific PCR, formatted as

```
INIT/<hash-algorithm> <hex-digest>
```
Where,
- `<hash-algorithm>`: may be `sha256`, `sha384`, or `sha512`.
- `<hex-digest>` is the base16-encoded PCR register value. The length MUST be aligned with the `<hash-algorithm>`. Padding with zeros or truncation MUST be applied if necessary to align with the digest length.

__Event Entry__ records specific events in the format
```
<Domain> <Operation> <Content>
```

Where,
- `Domain`: the event domain, RECOMMENDED to be a URI.
- `Operation`: the specific operation within the domain.
- `Content`: detailed context of the operation.

The three fields are separated by spaces. Each field MUST not contain spaces or delimiters and MUST be composed of [printable character](https://www.ascii-code.com/characters/printable-characters).
The three fields are defined by the specific application that calls AA to record events.

### Confidential Containers Event Spec

The Confidential Containers Event Spec (CoCo Event Spec) builds upon the AAEL framework, specifying event types pertinent to the unique context of Confidential Containers. 

This specification encompasses events closely tied to the lifecycle of Confidential Containers in guest. By focusing on these lifecycle events, the CoCo Event Spec ensures comprehensive monitoring and verification of critical container operations within secure computing environments. 

```
                                                                    
┌─────────────────────────────────────┐                             
│                                     │                             
│       ┌────────────────────┐        │                             
│       │ Kata-Agent/ASR/CDH │        │                             
│       └──────────┬─────────┘        │                             
│                  │                  │                             
│                  │                  │                             
│                  │                  │                             
│       ┌──────────▼──────────┐       │      ┌─────────────────────┐
│       │                     │       │      │                     │
│       │  Attestation Agent  ├───────┼─────►│ Attestation Service │
│       │                     │       │      │                     │
│       └───┬─────────┬───────┘       │      └─────────────────────┘
│           │         │               │                             
│           │         ▼               │                             
│    Extend │     ┌──────┐            │                             
│           │     │ AAEL │            │                             
│           │     └──────┘            │                             
│     ┌─────▼───────────────────┐     │                             
│     │ Runtime Measurements/PCR│     │                             
│     └─────────────────────────┘     │                             
│                                     │                             
│           Confidential VM           │                             
└─────────────────────────────────────┘                             
```

It is designed to be a flexible and extensible format that can be used to represent a variety of events in a Confidential Container environment.
The CoCo Event Spec is a concrete `Domain`, `Operation`, `Content` definition based on the AAEL specification.

CoCo events MUST have a `domain` set as `github.com/confidential-containers`.

Content fields MUST be in JSON format, without spaces or delimiters.

Concrete supported `Operation`s and `Content`s are defined in the following table:
| Operation | Content | Description | Content Example |
| --- | --- | --- | --- |
| `PullImage` | `{"image":"<image-reference>","digest":"<digest>:<hex>"}` | An image pulling event with image reference and manifest digest | `{"image":"alpine","digest":"sha256:0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"}` |

It's welcomed to add more events by making PRs.

## References

[1] https://lore.kernel.org/linux-coco/42c5eba9-381b-4639-9131-f645b375d235@linux.intel.com/T/#m086550ee8ca4d0127657ca8a467bf7cf170bfb74