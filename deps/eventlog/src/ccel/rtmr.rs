use crate::CcEventLog;
use crate::TcgAlgorithm;
use anyhow::{bail, Result};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::result::Result::Ok;

const RTMR_LENGTH_BY_BYTES: usize = 48;

#[derive(Debug, Clone)]
pub struct Rtmr {
    pub data: Vec<Vec<u8>>,
}

impl Rtmr {
    pub fn integrity_check(&self, rtmr_from_quote: Vec<Vec<u8>>) -> Result<()> {
        for (index, quote_value) in rtmr_from_quote.iter().enumerate() {
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

        let empty_data_len = result.keys().max().map(|k| (*k + 1).max(4)).unwrap_or(4);
        let mut data: Vec<Vec<u8>> = vec![vec![0u8; RTMR_LENGTH_BY_BYTES]; empty_data_len as usize];

        // Eliminate rtmr 0 from ccel result as it should not be compared
        let mut sorted_keys: Vec<u32> = result.keys().copied().filter(|key| *key > 0).collect();
        sorted_keys.sort();

        for index in sorted_keys {
            if let Some(value) = result.get(&index) {
                data[(index - 1) as usize] = value.to_vec();
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
    use crate::ccel::rtmr::Rtmr;
    use crate::ccel::tcg_enum::{TcgAlgorithm, TcgEventType};
    use crate::{CcEventLog, ElDigest, EventDetails, EventlogEntry};
    use rstest::rstest;
    use std::fs;

    #[rstest]
    #[case("./test_data/CCEL_data",
    vec![
        String::from("2dc712306a963eadb894ad47dbaa17df44814151555aee11cbb843becca88950ffd079664902e6f22c66f7c8213543f4"),
        String::from("0fa3be56af61208bbd179dc7b124988eb929319154663c539d6f46445ecac2fec287075047ff7bd1922829fec28cd3cf"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        ])]
    #[case("./test_data/CCEL_data_ovmf",
    vec![
        String::from("8566f998798db09443b244c62de9a3041fb02e2e6936c4396d784bba2e90177329ec5aba3bb484404f2ab9cc90abe193"),
        String::from("775b9f6bfe99f8a31396f0d0218e67ffa796d3b96ccf961cbb0deba48c79c00f082cda1a5567c1c16305f1fc210c13c6"),
        String::from("94eaf7a7bf398ed8d888c91057ae0261802e4f3df084213a76ca7f0b5055ac9d2241de43cd58d9e8b49c503bbf25f34a"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    ])]
    #[case("./test_data/CCEL_data_grub",
    vec![
        String::from("cec0a104f691f60da2387fea3c2de00c4ac035e2bb479ff02edcce69039d9e9907f0b3e55031da3dc7038f423adebd79"),
        String::from("6c289e0c62182d41ebe97bdbc9872d10998a08eaa86adcdc684001a363207ee72942c7522cdf00a4bbc3d784bed7b670"),
        String::from("08919d017ba0e52cd6d966351c7de16fe76c1d3d3d3da4554239e4c7d16cb8b82a94e7eaea3a0e6e18eb690b999fd31e"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    ])]
    #[case("./test_data/CCEL_data_gcp",
    vec![
        String::from("3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304f"),
        String::from("204d49f78d29918fe7b2f694e76653861a0c2a018987d2c3a54266eff737232524cf0af68c4d180e2f8c2c0937f21967"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    ])]
    #[case::gke_with_rtmr_0_no_action("./test_data/CCEL_data_grub_gke",
    vec![
        String::from("bc9945139042cf2cc75caf920aa57f14884ecfd7e893bccc51250c8ce90eb53ce72741e6adaa18183eb1331a87d4544a"),
        String::from("c17cb288a4dee302bb9ed8d27257a168f3264ad68cab53757f37eeaa7039657fa887cad65cf910e0fdc435ff110f8a7b"),
        String::from("334aeba2c985f8886cea97d1ecffbd512769d528b9a94009583db667ad7d2faa7d37fa145d75b192ceee2d2f10b2eb6d"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    ])]
    fn test_rtmr_integrity(#[case] test_data: &str, #[case] rtmrs: Vec<String>) {
        let ccel_bin = fs::read(test_data).unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();
        let rtmr_result = Rtmr::try_from(ccel);

        let rtmr_from_quote: Vec<Vec<u8>> =
            rtmrs.iter().map(|it| hex::decode(it).unwrap()).collect();

        assert!(rtmr_result.is_ok());
        let integrity = rtmr_result
            .expect("Result is ok")
            .integrity_check(rtmr_from_quote);
        assert!(integrity.is_ok());
    }

    #[rstest]
    #[case("./test_data/CCEL_data_gcp",
    vec![
        String::from("3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304d"),
        String::from("204d49f78d29918fe7b2f694e76653861a0c2a018987d2c3a54266eff737232524cf0af68c4d180e2f8c2c0937f21967"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    ],
    0,
    String::from("3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304f")
    )]
    #[case("./test_data/CCEL_data",
     vec![
        String::from("2dc712306a963eadb894ad47dbaa17df44814151555aee11cbb843becca88950ffd079664902e6f22c66f7c8213543f4"),
        String::from("0fa3be56af61208bbd179dc7b124988eb929319154663c539d6f46445ecac2fec287075047ff7bd1922829fec28cd3cf"),
        String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        String::from("")
    ],
    3,
    String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    )]
    #[case::uneven_rtmrs("./test_data/CCEL_data",
    vec![
        String::from("2dc712306a963eadb894ad47dbaa17df44814151555aee11cbb843becca88950ffd079664902e6f22c66f7c8213543f4"),
        String::from("0fa3be56af61208bbd179dc7b124988eb929319154663c539d6f46445ecac2fec287075047ff7bd1922829fec28cd3cf"),
        String::from("7468697369736d7974657374207768696368206973206e6f742061637475616c20726573756c742066726f6d2072746d"),
        String::from(""),
        String::from("")
    ],
    2,
    String::from("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    )]
    fn test_rtmr_integrity_error(
        #[case] test_data: &str,
        #[case] rtmrs: Vec<String>,
        #[case] wrong_rtmr_num: usize,
        #[case] ccel_wrong_rtmr_value: String,
    ) {
        let ccel_bin = fs::read(test_data).unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();
        let rtmr_result = Rtmr::try_from(ccel);

        let rtmr_from_quote: Vec<Vec<u8>> =
            rtmrs.iter().map(|it| hex::decode(it).unwrap()).collect();

        assert!(rtmr_result.is_ok());

        let integrity = rtmr_result
            .expect("Result is ok")
            .integrity_check(rtmr_from_quote);

        let expected_err_msg = format!(
            "CCEL eventlog does not pass RTMR [{}] check. CCEL value: {}, Quote value: {}",
            wrong_rtmr_num,
            ccel_wrong_rtmr_value,
            rtmrs.get(wrong_rtmr_num).unwrap()
        );

        assert!(integrity.is_err());
        assert_eq!(integrity.unwrap_err().to_string(), expected_err_msg);
    }

    #[test]
    fn test_rtmr_with_more_entries() {
        let mut event_log = Vec::new();
        event_log.push(EventlogEntry {
            index: 0,
            event_type: TcgEventType::EvNoAction,
            digests: vec![ElDigest { alg: TcgAlgorithm::Sha384, digest: hex::decode("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap() }],
            event: "".to_string(),
            details: EventDetails::empty()
        });
        event_log.push(EventlogEntry {
            index: 1,
            event_type: TcgEventType::EvEfiHandoffTables2,
            digests: vec![ElDigest { alg: TcgAlgorithm::Sha384, digest: hex::decode("458994daa60deac8dea19dba79748f6ff93fd0aebb8e3e0be5a65eb12309d342c3ce31cc67af7bbd22af1a44e7d9fe21").unwrap() }],
            event: "".to_string(),
            details: EventDetails::empty()
        });
        event_log.push(EventlogEntry {
            index: 2,
            event_type: TcgEventType::EvAction,
            digests: vec![ElDigest { alg: TcgAlgorithm::Sha384, digest: hex::decode("77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71").unwrap() }],
            event: "".to_string(),
            details: EventDetails::empty()
        });
        event_log.push(EventlogEntry {
            index: 3,
            event_type: TcgEventType::EvIpl,
            digests: vec![ElDigest { alg: TcgAlgorithm::Sha384, digest: hex::decode("2fdc8531577607d99031d70fb3063e9e4aecf50a7eaa9c2b0bcda5c5a6e111302996c138465920cadea4416d36089651").unwrap() }],
            event: "".to_string(),
            details: EventDetails::empty()
        });
        event_log.push(EventlogEntry {
            index: 4,
            event_type: TcgEventType::EvAction,
            digests: vec![ElDigest { alg: TcgAlgorithm::Sha384, digest: hex::decode("df6024107c34b0b6d06b01e5515464eee8158cf440c6c6c1a6be273746a11fbac84960870622768ecbfd7a3061939416").unwrap() }],
            event: "".to_string(),
            details: EventDetails::empty()
        });
        event_log.push(EventlogEntry {
            index: 5,
            event_type: TcgEventType::EvAction,
            digests: vec![ElDigest { alg: TcgAlgorithm::Sha384, digest: hex::decode("1bcd2ed729fb9dc7b1a168ab4a6e2e04b66d7405ea2622d666780ec9f1eceb031010f0bdf37c46ab34e6a7201b73d5ae").unwrap() }],
            event: "".to_string(),
            details: EventDetails::empty()
        });
        let ccel = CcEventLog { log: event_log };
        let rtmr_result = Rtmr::try_from(ccel);
        assert!(rtmr_result.is_ok());
        let rtmr = rtmr_result.ok().unwrap();

        let rtmrs = vec![
            b"75be6f5a6b972d3c896ab2c99fc6348ba1f7b6713133af82346aedc0390b25bbed0c8fb3cecd9eef2a4998a9be162569",
            b"8032dedfdb8373b9bf18849c61543d2ed4fd555ffb0028634689a13fc4de798ff904ccded77c2d72259ab9777a17d7bd",
            b"7a8b253ff8dbe719c426201b04cba3bc92728c6b037ebc9bdff701fa45c6ab508ea1cbb9e9664e3d67748eb0de47ff53",
            b"4704c993a59a90adf83ac8e03695ec79743e709b36bd30cab8b55ad74bcf5a2c2900731966a9c8f2e5e87260e5a22100",
            b"1212cc75e29d3c974f0f3179b67faae64a0576979ef31c8e4ce5035447fabc21b69f286cdb7301601d9d6fa7118df966"
        ];

        let part_struct_rtmr_check: Vec<Vec<u8>> = rtmrs
            .iter()
            .take(rtmrs.len() - 2)
            .map(|it| hex::decode(it).unwrap())
            .collect();

        let integrity_part = rtmr.clone().integrity_check(part_struct_rtmr_check);

        assert!(integrity_part.is_ok(), "Should check rtmr 0-3");

        let entire_struct_rtmr_check: Vec<Vec<u8>> =
            rtmrs.iter().map(|it| hex::decode(it).unwrap()).collect();

        let integrity = rtmr.integrity_check(entire_struct_rtmr_check);

        assert!(integrity.is_ok(), "Should check rtmr 0-4");
    }
}
