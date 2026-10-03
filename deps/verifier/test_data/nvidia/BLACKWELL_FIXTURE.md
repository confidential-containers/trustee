# Blackwell fixture provenance

The Blackwell report and certificate fixtures in this directory were captured
from an NVIDIA RTX PRO 6000 Blackwell Server Edition assigned to a
`kata-qemu-nvidia-gpu-snp` guest. The capture did not change CC mode or reset
the GPU. The report came directly from
`nvmlDeviceGetConfComputeGpuAttestationReport`, and the certificate chain came
from `nvmlDeviceGetConfComputeGpuCertificate`. NRAS and NVIDIA's RIM service
were not used.

- Driver: `595.58.03`
- VBIOS: `98.02.81.00.01`
- Nonce: `4cff7f5380ead8fad8ec2c531c110aca4302a88f603792801a8ca29ee151af2e`
- Raw report size: 4140 bytes
- Raw report SHA-256: `73c76d3e1b182f55ac88ca650dde7f58abcd8ff1eb32bb76ab8988203f047511`
- Certificate-chain size: 4903 bytes
- Certificate-chain SHA-256: `fe1bf21df53094d452dd6d1727d93a1bc3f44e8a4d504ad83bbe5548290ffc38`
- Leaf certificate serial (UEID):
  `408762037488965241743361667085904172082023387885`
- FWID: `9b92cc3e53b9265259e1abde163653288c2474fcafd8e5c0fd62ce9c9036fb62723fe3715b50f4ac27c68b62e2fd9240`

The exact report and chain passed both NVIDIA local verifier implementations:

- nvtrust tag `2026.06.04.001`, commit
  `0c5d627313037c1e577d05a232e79394a41b2c21`
- NVIDIA Attestation SDK tag `2026.06.09`, commit
  `9d12801cea8a198ea0f29640dfaf8a4017c841c5`, using NVAT `1.2.2`

Both implementations reported the same FWID, 64 measurements, valid report
signature, valid nonce, and valid certificate chain.

The report contains opaque field IDs
`3, 4, 6, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 33, 34, 35, 36`.
All were already represented by Trustee's `OpaqueDataType`.

No B200 fixture or post-CC-mode-toggle fixture was available. Those cases must
not be inferred from this capture.

## Publication note

The fixtures contain public certificates and a signed report for the fixed
nonce above. They contain no private key, workload secret, DEK, host name, or
captured device UUID, and the report cannot satisfy a fresh nonce challenge.
