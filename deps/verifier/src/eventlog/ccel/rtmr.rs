use crate::eventlog::ccel::tcg_enum::TcgAlgorithm;
use crate::eventlog::ccel::CcEventLog;
use anyhow::bail;
use anyhow::*;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::result::Result::Ok;

const RTMR_LENGTH_BY_BYTES: usize = 48;
const CHECK_RTMR_LIMIT: usize = 3;

#[derive(Debug, Clone)]
pub struct Rtmr {
    pub data: [Vec<u8>; 4],
}

impl Rtmr {
    pub fn integrity_check(&self, rtmr_from_quote: [Vec<u8>; 4]) -> Result<()> {
        for (index, quote_value) in rtmr_from_quote.iter().enumerate().take(CHECK_RTMR_LIMIT) {
            let ccel_value = &self.data[index];
            if ccel_value != quote_value {
                bail!(
                    "CCEL eventlog does not pass RTMR [{}] check. CCEL value: {}, Quote value: {}",
                    index,
                    hex::encode(ccel_value),
                    hex::encode(quote_value)
                );
            }
        }

        Ok(())
    }
}

impl TryFrom<CcEventLog> for Rtmr {
    type Error = anyhow::Error;

    fn try_from(data: CcEventLog) -> anyhow::Result<Self> {
        let mut result: HashMap<u32, [u8; RTMR_LENGTH_BY_BYTES]> = HashMap::new();

        for entry in data.log.into_iter() {
            let digest = &entry.digests[0].digest;

            let mr_value = result
                .entry(entry.index)
                .or_insert([0u8; RTMR_LENGTH_BY_BYTES]);

            let hash = accumulate_hash(
                entry.digests[0].alg,
                mr_value.clone().to_vec(),
                digest.as_slice(),
            )?;

            mr_value.copy_from_slice(&hash);
        }

        let mut data: [Vec<u8>; 4] = [
            vec![0u8; RTMR_LENGTH_BY_BYTES],
            vec![0u8; RTMR_LENGTH_BY_BYTES],
            vec![0u8; RTMR_LENGTH_BY_BYTES],
            vec![0u8; RTMR_LENGTH_BY_BYTES],
        ];

        for index in 1..5 {
            if let Some(value) = result.get(&index) {
                data[index as usize - 1] = value.to_vec();
            }
        }

        Ok(Rtmr { data })
    }
}

fn accumulate_hash(alg: TcgAlgorithm, materials: Vec<u8>, digest: &[u8]) -> Result<Vec<u8>> {
    let result = match alg {
        TcgAlgorithm::Sha256 => hash_with::<Sha256>(&materials, digest),
        TcgAlgorithm::Sha384 => hash_with::<Sha384>(&materials, digest),
        TcgAlgorithm::Sha512 => hash_with::<Sha512>(&materials, digest),
        _ => bail!("Unsupported Hash algorithm {:?}", alg),
    };

    Ok(result)
}

fn hash_with<D: Digest + Default>(materials: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut hasher = D::default();
    hasher.update(materials);
    hasher.update(digest);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::fs;

    #[rstest]
    #[case("./test_data/CCEL_data",
        b"2dc712306a963eadb894ad47dbaa17df44814151555aee11cbb843becca88950ffd079664902e6f22c66f7c8213543f4",
        b"0fa3be56af61208bbd179dc7b124988eb929319154663c539d6f46445ecac2fec287075047ff7bd1922829fec28cd3cf",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        false
    )]
    #[case("./test_data/CCEL_data_ovmf",
        b"8566f998798db09443b244c62de9a3041fb02e2e6936c4396d784bba2e90177329ec5aba3bb484404f2ab9cc90abe193",
        b"775b9f6bfe99f8a31396f0d0218e67ffa796d3b96ccf961cbb0deba48c79c00f082cda1a5567c1c16305f1fc210c13c6",
        b"94eaf7a7bf398ed8d888c91057ae0261802e4f3df084213a76ca7f0b5055ac9d2241de43cd58d9e8b49c503bbf25f34a",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        false
    )]
    #[case("./test_data/CCEL_data_grub",
        b"cec0a104f691f60da2387fea3c2de00c4ac035e2bb479ff02edcce69039d9e9907f0b3e55031da3dc7038f423adebd79",
        b"6c289e0c62182d41ebe97bdbc9872d10998a08eaa86adcdc684001a363207ee72942c7522cdf00a4bbc3d784bed7b670",
        b"08919d017ba0e52cd6d966351c7de16fe76c1d3d3d3da4554239e4c7d16cb8b82a94e7eaea3a0e6e18eb690b999fd31e",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        false
    )]
    #[case(
        "./test_data/CCEL_data_gcp",
        b"3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304f",
        b"204d49f78d29918fe7b2f694e76653861a0c2a018987d2c3a54266eff737232524cf0af68c4d180e2f8c2c0937f21967",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        false
    )]
    #[case(
        "./test_data/CCEL_data_gcp",
        b"3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304d",
        b"204d49f78d29918fe7b2f694e76653861a0c2a018987d2c3a54266eff737232524cf0af68c4d180e2f8c2c0937f21967",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        true
    )]
    #[case("./test_data/CCEL_data",
        b"2dc712306a963eadb894ad47dbaa17df44814151555aee11cbb843becca88950ffd079664902e6f22c66f7c8213543f4",
        b"0fa3be56af61208bbd179dc7b124988eb929319154663c539d6f46445ecac2fec287075047ff7bd1922829fec28cd3cf",
        b"",
        b"",
        true
    )]
    fn test_rtmr(
        #[case] test_data: &str,
        #[case] rtmr0: &[u8],
        #[case] rtmr1: &[u8],
        #[case] rtmr2: &[u8],
        #[case] rtmr3: &[u8],
        #[case] expect_error: bool,
    ) {
        let ccel_bin = fs::read(test_data).unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();
        let rtmr_result = Rtmr::try_from(ccel);

        let rtmr_from_quote: [Vec<u8>; 4] = [
            hex::decode(rtmr0).unwrap(),
            hex::decode(rtmr1).unwrap(),
            hex::decode(rtmr2).unwrap(),
            hex::decode(rtmr3).unwrap(),
        ];

        assert!(rtmr_result.is_ok());
        let integrity = rtmr_result
            .expect("Result is ok")
            .integrity_check(rtmr_from_quote);
        assert_eq!(expect_error, integrity.is_err());
    }
}
