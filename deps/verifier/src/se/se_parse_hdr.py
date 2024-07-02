# Copyright (C) Copyright IBM Corp. 2024
#
# SPDX-License-Identifier: Apache-2.0
#

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib
import sys
import struct


def parse_certificate(cert_path):
    """Parse the certificate from file path and return the public key."""
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert.public_key()

def ec_point_to_affine_coordinates(public_key):
    """Convert EC public key to affine coordinates (x, y)."""
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        # Get the uncompressed point bytes
        point = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        curve = public_key.curve
        x_bytes = point[1:curve.key_size//8+2]  # skip the first byte (0x04)
        y_bytes = point[curve.key_size//8+2:]
        return x_bytes, y_bytes
    else:
        raise ValueError("Invalid EC public key type")

def bn_bn2binpad(bn, size):
    """Convert BN to binary padded format."""
    bn_bytes = bn.to_bytes((bn.bit_length() + 7) // 8, byteorder='big')
    if len(bn_bytes) < size:
        padded_bytes = b'\x00' * (size - len(bn_bytes)) + bn_bytes
    elif len(bn_bytes) > size:
        padded_bytes = bn_bytes[-size:]
    else:
        padded_bytes = bn_bytes
    return padded_bytes

def generate_sha256_hash(data):
    """Generate SHA-256 hash of input data."""
    sha256_hash = hashlib.sha256(data).hexdigest()
    return sha256_hash

def bytes_to_hex_string(byte_data):
    """Convert bytes to hex string."""
    return ''.join(f'{b:02x}' for b in byte_data)

def parse_img_phkh_from_hkd(filename):
    # Parse certificate and extract public key
    public_key = parse_certificate(filename)

    # Get affine coordinates
    x_bytes, y_bytes = ec_point_to_affine_coordinates(public_key)

    # Convert x_bytes and y_bytes to binary padded format
    x_bin = bn_bn2binpad(int.from_bytes(x_bytes, byteorder='big'), 80)  # 66 bytes for P-521 curve
    y_bin = bn_bn2binpad(int.from_bytes(y_bytes, byteorder='big'), 80)

    # Log x_bin and y_bin
    x_bin_str = bytes_to_hex_string(x_bin)
    y_bin_str = bytes_to_hex_string(y_bin)

    # Concatenate x_bin and y_bin
    ecdh_data = x_bin + y_bin

    # Log concatenated data
    ecdh_data_str = bytes_to_hex_string(ecdh_data)

    # Calculate SHA-256 hash
    hkd_phkh = generate_sha256_hash(ecdh_data)
    return hkd_phkh

def parse_hdr(hdr_file, hkd_file):
    with open(hdr_file, 'rb') as f:

        hkd_phkh = parse_img_phkh_from_hkd(hkd_file)
        key_slot_used_idx = -1

        # Read the entire header based on the size defined in the structure
        # https://github.com/ibm-s390-linux/s390-tools/blob/master/genprotimg/src/include/pv_hdr_def.h
        header_size = 8 + 4 + 4
        # pv_hdr_head size 416
        pv_hdr_head_size = 8 + 4 + 4 + 12 + 4 + 8 + 8 + 8 + 8 + 160 + 64 + 64 + 64

        after_key_slot_size = 144
        # pv_hdr_key_slot digest_key + wrapped_key = phkh
        phkh_size = 32

        hdr_data = f.read(header_size)

        # Unpack the header fields
        fields = struct.unpack('8sII', hdr_data)

        magic, version, phs = fields
        # The last 16 bits is the image tag
        f.seek(-16, 2)
        image_tag = f.read(16)
        # Print the extracted fields

        print(f"Magic: {magic.decode('ascii')}")
        print(f"phs: {phs}")

        f.seek(pv_hdr_head_size)

        length_phkh_data = phs - pv_hdr_head_size - after_key_slot_size
        phkh_data = f.read(length_phkh_data)

        # Define the struct format (32 bytes for digest_key, 32 bytes for wrapped_key, 16 bytes for tag)
        struct_format = '32s32s16s'

        # Calculate the size of each struct
        struct_size = struct.calcsize(struct_format)

        for i in range(0, len(phkh_data), struct_size):
            if i + struct_size > len(phkh_data):
                break
            chunk = phkh_data[i:i + struct_size]
            digest_key, wrapped_key, tag = struct.unpack(struct_format, chunk)
            if digest_key.hex() == hkd_phkh:
                 key_slot_used_idx = i
                 print(f" ========Host Key Document Hash used in this slot========= ")
            print(f"  Key Slot: {i//80 + 1}:")
            print(f"  image_phkh: {digest_key.hex()}")
            print(f"  wrapped_key: {wrapped_key.hex()}")
            print(f"  tag: {tag.hex()}")
        # if the 1 slot selected, the idx is 0
        if key_slot_used_idx > -1:
            chunk_used = phkh_data[key_slot_used_idx:key_slot_used_idx + struct_size]
            digest_key, wrapped_key, tag = struct.unpack(struct_format, chunk_used)
            print(f" ========Host Key Document Hash used in this slot========= ")
            print(f"  Key Slot: {key_slot_used_idx//80 + 1}:")
            print(f"  wrapped_key: {wrapped_key.hex()}")
            print(f" HKD tag: {tag.hex()}")
            print(f"  Copy below value and set in rvps ")
            print(f"  ================================================ ")
            print(f"  se.image_phkh: {digest_key.hex()}")
        else:
            print(f" The HKD file not included when build the SE image ")
    

        print(f"  se.version: {version}")
        print(f"  se.tag: {image_tag.hex()}")
        print(f"  se.attestation_phkh: {hkd_phkh}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <SE image header file: hdr.bin   Host Key Document file: HKD.crt >")
        sys.exit(1)

    hdr_file = sys.argv[1]
    hkd_file = sys.argv[2]
    parse_hdr(hdr_file, hkd_file)
