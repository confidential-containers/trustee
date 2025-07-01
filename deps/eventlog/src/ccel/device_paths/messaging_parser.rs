use super::{DevicePathParser, DeviceSubTypeParser};
use anyhow::{anyhow, bail, Result};
use scroll::{Pread, LE};
use std::net::Ipv4Addr;

/// Parser for Type 3 - Messaging Device Path.
/// Define in section 10.3.4 of <https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#messaging-device-path>
enum MessagingSubType {
    FibreChannelEx,
    Usb,
    Mac,
    Ipv4,
    // Add more subtype parsers here as needed
}

impl MessagingSubType {
    fn from_u8(sub_type: u8) -> Result<Self> {
        match sub_type {
            0x15 => Ok(MessagingSubType::FibreChannelEx),
            0x05 => Ok(MessagingSubType::Usb),
            0x0B => Ok(MessagingSubType::Mac),
            0x0C => Ok(MessagingSubType::Ipv4),
            _ => Err(anyhow!("Unknown Messaging subtype: {:#04x}", sub_type)),
        }
    }

    fn parse(&self, data: &[u8]) -> Result<String> {
        let parser: &dyn DeviceSubTypeParser = match self {
            MessagingSubType::FibreChannelEx => &FibreChannelExParser,
            MessagingSubType::Usb => &UsbParser,
            MessagingSubType::Mac => &MacParser,
            MessagingSubType::Ipv4 => &Ipv4Parser,
        };

        parser.parse(data)
    }
}

pub struct MessagingParser;

impl DevicePathParser for MessagingParser {
    fn parse(&self, sub_type: u8, data: &[u8]) -> Result<String> {
        MessagingSubType::from_u8(sub_type).and_then(|path| path.parse(data))
    }
}

pub struct FibreChannelExParser;

impl DeviceSubTypeParser for FibreChannelExParser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        if data.len() < 16 {
            bail!("Fibre channel data is too short");
        }

        let wwn = &data[0..8];
        let lun = &data[8..16];

        Ok(format!(
            "FibreEx(0x{},0x{})",
            hex::encode(wwn),
            hex::encode(lun)
        ))
    }
}

pub struct UsbParser;

impl DeviceSubTypeParser for UsbParser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        if data.len() < 2 {
            bail!("USB data is too short");
        }

        let parent_hub_port_num = &data[0];
        let controller_int_number = &data[1];

        Ok(format!(
            "USB({},{})",
            parent_hub_port_num, controller_int_number
        ))
    }
}

pub struct MacParser;

impl DeviceSubTypeParser for MacParser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        if data.len() != 33 {
            bail!("MAC data is too short");
        }

        let mac_address_padded = &data[0..31];
        let binding = hex::encode(mac_address_padded);
        let mac_address = binding.trim_end_matches('0').to_uppercase();
        let if_type = &data[32];

        Ok(format!("Mac({},{:#04x})", mac_address, if_type))
    }
}

pub struct Ipv4Parser;

impl DeviceSubTypeParser for Ipv4Parser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        let mut index = 0;

        let local_ip = data
            .gread_with(&mut index, LE)
            .map(Ipv4Addr::from_bits)
            .map_err(|e| anyhow::anyhow!("Failed to read IPv4 local address: {:?}", e))?;
        let remote_ip = data
            .gread_with(&mut index, LE)
            .map(Ipv4Addr::from_bits)
            .map_err(|e| anyhow::anyhow!("Failed to read IPv4 remote address: {:?}", e))?;
        let _local_port: u16 = data
            .gread_with(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read IPv4 local port: {:?}", e))?;
        let _remote_port: u16 = data
            .gread_with(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read IPv4 remote port: {:?}", e))?;
        let protocol = match data
            .gread_with::<u16>(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read IPv4 protocol: {:?}", e))?
        {
            6 => "TCP",
            17 => "UDP",
            _ => "",
        };
        let ip_addr_type = match data
            .gread_with::<u8>(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read IPv4 address type: {:?}", e))?
        {
            0 => "DHCP",
            1 => "Static",
            _ => "",
        };

        let gateway_ip_address: u32 = data
            .gread_with(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read IPv4 gateway: {:?}", e))?;
        let subnet_mask: u32 = data
            .gread_with(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read IPv4 subnet: {:?}", e))?;
        let gateway_subnet = if gateway_ip_address != 0 || subnet_mask != 0 {
            format!(",{},{}", gateway_ip_address, subnet_mask)
        } else {
            "".to_string()
        };

        Ok(format!(
            "IPv4({},{},{},{}{})",
            remote_ip, protocol, ip_addr_type, local_ip, gateway_subnet
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::usb(5, b"0000", "USB(0,0)")]
    #[case::mac(
        11,
        b"001320f5fa77000000000000000000000000000000000000000000000000000001",
        "Mac(001320F5FA77,0x01)"
    )]
    #[case::ipv4(
        12,
        b"0100A8C06400A8C00000BC0C0600010000000000000000",
        "IPv4(192.168.0.100,TCP,Static,192.168.0.1)"
    )]
    #[case::fibre_ex(
        21,
        b"00010203040506070001020304050607",
        "FibreEx(0x0001020304050607,0x0001020304050607)"
    )]
    fn test_formatter(#[case] sub_type: u8, #[case] data: &[u8], #[case] expected_result: &str) {
        let vendor_data = hex::decode(data).unwrap();
        let actual = MessagingParser.parse(sub_type, &vendor_data);
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), expected_result);
    }

    #[rstest]
    #[case::atapi(1, "Unknown Messaging subtype: 0x01")]
    #[case::scsi(2, "Unknown Messaging subtype: 0x02")]
    #[case::fibre_channel(3, "Unknown Messaging subtype: 0x03")]
    #[case::i1394(4, "Unknown Messaging subtype: 0x04")]
    #[case::i2o(6, "Unknown Messaging subtype: 0x06")]
    #[case::infiniband(9, "Unknown Messaging subtype: 0x09")]
    #[case::msg_vendor(10, "Unknown Messaging subtype: 0x0a")]
    #[case::ipv6(13, "Unknown Messaging subtype: 0x0d")]
    #[case::uart(14, "Unknown Messaging subtype: 0x0e")]
    #[case::usbclass(15, "Unknown Messaging subtype: 0x0f")]
    #[case::usbwwid(16, "Unknown Messaging subtype: 0x10")]
    #[case::device_logical_unit(17, "Unknown Messaging subtype: 0x11")]
    #[case::sata(18, "Unknown Messaging subtype: 0x12")]
    #[case::iscsi(19, "Unknown Messaging subtype: 0x13")]
    #[case::vlan(20, "Unknown Messaging subtype: 0x14")]
    #[case::sas_ex(22, "Unknown Messaging subtype: 0x16")]
    #[case::nvme(23, "Unknown Messaging subtype: 0x17")]
    #[case::uri(24, "Unknown Messaging subtype: 0x18")]
    #[case::ufs(25, "Unknown Messaging subtype: 0x19")]
    #[case::sd(26, "Unknown Messaging subtype: 0x1a")]
    #[case::bluetooth(27, "Unknown Messaging subtype: 0x1b")]
    #[case::wifi(28, "Unknown Messaging subtype: 0x1c")]
    #[case::emmc(29, "Unknown Messaging subtype: 0x1d")]
    #[case::bluetooth_le(30, "Unknown Messaging subtype: 0x1e")]
    #[case::dns(31, "Unknown Messaging subtype: 0x1f")]
    #[case::nvdimmservice(32, "Unknown Messaging subtype: 0x20")]
    #[case::restservice(33, "Unknown Messaging subtype: 0x21")]
    #[case::nvmeo_fnamespace(34, "Unknown Messaging subtype: 0x22")]
    fn unsupported_test(#[case] sub_type: u8, #[case] expected_msg: &str) {
        let actual = MessagingParser.parse(sub_type, b"0000");
        assert!(actual.is_err());
        assert_eq!(actual.unwrap_err().to_string(), expected_msg);
    }
}
