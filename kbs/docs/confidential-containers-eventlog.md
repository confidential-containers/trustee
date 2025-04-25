# Specification for Attestation Agent Event Log

## Introduction

The [Confidential Computing Eventlog (CCEL)](https://uefi.org/specs/UEFI/2.11/38_Confidential_Computing.html) framework plays a crucial role in establishing trust during the OS boot-up phase, ensuring that foundational system components are verified for integrity and security. It's based on `EFI_TCG2_EVENT_LOG_FORMAT_TCG_2` format (a.k.a `Crypto Agile Log Entry Format`) specified by [TCG EFI Protocol Specification (Section 5.2)](https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf) and [TCG PC Client Platform Firmware Profile Specification (Section 9.2.2)](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_05_3feb20.pdf). It provides detailed event types covering pre-OS events. To further extend this trust beyond the boot process, the Attestation Agent Eventlog (AAEL) format is introduced to provide comprehensive measurement capabilities for the post-OS phase. The AAEL framework is designed with scalability in mind, allowing broad support for numerous types of measurement events, including memory operations, network transactions, filesystem activities, and container-related processes.

AAEL can be seamlessly integrate into `EFI_TCG2_EVENT_LOG_FORMAT_TCG_2`, enriching the existing event logging framework and providing a holistic approach to security and integrity in computing environments. Ideally, AAEL would be embedded into the Kernel-maintained Eventlog, allowing for a unified logging system. However, the Kernel community has not yet provided clear guidance on whether future versions will support Eventlog and what format they might adopt, whether it be TCG2 or another format[1]. Given this uncertainty, we are currently presenting the AAEL format independently. Decisions regarding how it will be stored within the underlying Eventlog will be addressed during implementation as more information becomes available. Because of these reasons, parts of this specification are subject to change or to be removed.

## Architecture

The architecture supporting AAEL seamlessly integrates with existing confidential computing systems,
providing a robust event logging and verification framework above the kernel level within CVMs. The [Attestation Agent (AA)](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent) is integral to this process, recording events within the AAEL framework and securely binding logs to hardware runtime measurement registers.

It receives logging requests from system components.

These callers record events following the spec-defined AAEL Event, ensuring consistency and reliability in log data.

Trustee [CoCo Attestation Service (CoCo AS)](https://github.com/confidential-containers/trustee/tree/main/attestation-service) offers a flexible platform for processing AAEL logs in a generalized manner, ensuring compatibility with various confidential computing environments for diverse event verification.
Furthermore, AS can conduct detailed analysis and enforce policies for AAEL events, utilizing the AAEL Event Spec for precise validation and scrutiny. This capability supports the development and execution of advanced security policies, enhancing the appraisal of the VM state.

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

## Specifications

AAEL is a specification for event logging over guest kernel level.

### Attestation Agent Event Log (AAEL)

1. Binding of AAEL with Dynamic Measurement Registers

Entries recorded by AAEL are bound to a specific register value that ensures the integrity of logged events. When AAEL is integrated into an established Eventlog framework, such as the `EFI_TCG2_EVENT_LOG_FORMAT_TCG_2`, updates to the underlying registers follow the guidelines of the Eventlog's specifications, typically using the `EVENT` field to store AAEL entry.

With each new event added, an extend operation is performed on the designated register. When the platform supports a (v)TPM interface, this register corresponds to the (v)TPM's PCR register. On platforms exclusively utilizing TEE, the PCR is mapped to a specific [confidential computing measurement register](https://uefi.org/specs/UEFI/2.11/38_Confidential_Computing.html#virtual-platform-cc-event-log) according to platform-specific rules. This mapping ensures AAEL's applicability in both TEE and non-TEE environments.

For scenarios where AAEL is directly stored in a RAW format, the digest of the AAEL entry is directly used to extend the designated register.

2. AAEL Log Entry Format

AAEL log entries consist of two types: Event Entry and INIT Entry. 

__INIT Entry__ is recorded only once at the beginning of AAEL when AA first initializes, capturing the current value of a specific PCR, formatted as

```
INIT/<hash-algorithm> <hex-digest>
```
Where,
- `<hash-algorithm>`: may be `sha256`, `sha384`, or `sha512`.
- `<hex-digest>` is the base16-encoded PCR register value. The length MUST be aligned with the `<hash-algorithm>`. Padding with zeros or truncation **MUST** be applied if necessary to align with the digest length.

__Event Entry__ records specific events in the format
```
<Domain> <Operation> <Content>
```

Where,
- `Domain`: **Required**. The event domain, **RECOMMENDED** to be a URI.
- `Operation`: **Required**. The specific operation within the domain.
- `Content`: **Required**. Detailed context of the operation.

Event Format Requirements

- Both the `Domain` and `Operation` fields **MUST NOT** contain any [white space characters](https://www.ascii-code.com/characters/white-space-characters) 
- All three fields **MUST** consist solely of [printable characters](https://www.ascii-code.com/characters/printable-characters).
- The `Domain` and `Operation` fields are separated by a single Space (ASCII code `0x20`).
- The `Operation` and `Content` fields are separated by a single Space (ASCII code `0x20`).
- The `Content` field **MUST NOT** have any line feed character (LF, `\n`, ASCII code `0x0A`).
- Each line in the AAEL **MUST** terminate with a line feed character (LF, `\n`, ASCII code `0x0A`) and **MUST NOT** include any additional carriage return characters (CR, `\r`, ASCII code `0x0D`).

The semantic meaning of the three fields is defined by the specific component that calls AA to record events.

3. Measurement API

The Attestation Agent must provide an API to support AAEL recording, enabling integration with existing event logging frameworks.

```proto
// Extend the dynamic/runtime measurement with given materials. This would change the state
// of current TEE's status, e.g. TDX's RTMR, (v)TPM's PCR, by adding a record in eventlog.
message ExtendRuntimeMeasurementRequest {
    // The domain to which this event entry belongs. This domain is used to distinguish the semantics of log entries in different contexts.
    string Domain = 1;

    // Concrete operation type that this event entry records.
    string Operation = 2;

    // Detailed content of the operation that this event entry records.
    string Content = 3;

    // Which PCR will be extended with the hash of this entry.
    optional uint64 RegisterIndex = 4;
}
```

By default, the `RegisterIndex` is set to `17` due to its role in supporting the dynamic root of trust for measurement. Notably, PCR `17` is not registered in [Linux TPM PCR Registry](https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/). Additionally, [TCG TRUSTED BOOT CHAIN IN EDK II](https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html) specifies that __PCRs [17-22] represent the platform's dynamic root of trust for measurement (DRTM).__

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

CoCo events **MUST** have a `domain` set as `github.com/confidential-containers`.

The `Content` field **MUST** be a JSON.
The `Content` JSON **MUST** be canonicalized (according to the [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) scheme)

Concrete supported `Operation`s and `Content`s are defined in the following table:
| Operation | Content | Description | Content Example |
| --- | --- | --- | --- |
| `PullImage` | `{"image":"<image-reference>","digest":"<digest>:<hex>"}` | An image pulling event with image reference and manifest digest | `{"image":"alpine","digest":"sha256:0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"}` |

It's welcomed to add more events by making PRs.

## References

[1] https://lore.kernel.org/linux-coco/42c5eba9-381b-4639-9131-f645b375d235@linux.intel.com/T/#m086550ee8ca4d0127657ca8a467bf7cf170bfb74