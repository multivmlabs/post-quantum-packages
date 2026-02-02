//! Algorithm information registry.

use crate::oid;
use crate::types::{AlgorithmFamily, AlgorithmInfo, AlgorithmName, AlgorithmType};

const ALGORITHM_INFO: &[AlgorithmInfo] = &[
    AlgorithmInfo {
        name: AlgorithmName::MlKem512,
        oid: oid::ML_KEM_512,
        algorithm_type: AlgorithmType::Kem,
        family: AlgorithmFamily::MlKem,
        security_level: 1,
        public_key_size: 800,
        private_key_size: 1632,
        signature_size: None,
        ciphertext_size: Some(768),
    },
    AlgorithmInfo {
        name: AlgorithmName::MlKem768,
        oid: oid::ML_KEM_768,
        algorithm_type: AlgorithmType::Kem,
        family: AlgorithmFamily::MlKem,
        security_level: 3,
        public_key_size: 1184,
        private_key_size: 2400,
        signature_size: None,
        ciphertext_size: Some(1088),
    },
    AlgorithmInfo {
        name: AlgorithmName::MlKem1024,
        oid: oid::ML_KEM_1024,
        algorithm_type: AlgorithmType::Kem,
        family: AlgorithmFamily::MlKem,
        security_level: 5,
        public_key_size: 1568,
        private_key_size: 3168,
        signature_size: None,
        ciphertext_size: Some(1568),
    },
    AlgorithmInfo {
        name: AlgorithmName::MlDsa44,
        oid: oid::ML_DSA_44,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::MlDsa,
        security_level: 2,
        public_key_size: 1312,
        private_key_size: 2560,
        signature_size: Some(2420),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::MlDsa65,
        oid: oid::ML_DSA_65,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::MlDsa,
        security_level: 3,
        public_key_size: 1952,
        private_key_size: 4032,
        signature_size: Some(3309),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::MlDsa87,
        oid: oid::ML_DSA_87,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::MlDsa,
        security_level: 5,
        public_key_size: 2592,
        private_key_size: 4896,
        signature_size: Some(4627),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaSha2_128s,
        oid: oid::SLH_DSA_SHA2_128S,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 1,
        public_key_size: 32,
        private_key_size: 64,
        signature_size: Some(7856),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaSha2_128f,
        oid: oid::SLH_DSA_SHA2_128F,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 1,
        public_key_size: 32,
        private_key_size: 64,
        signature_size: Some(17088),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaSha2_192s,
        oid: oid::SLH_DSA_SHA2_192S,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 3,
        public_key_size: 48,
        private_key_size: 96,
        signature_size: Some(16224),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaSha2_192f,
        oid: oid::SLH_DSA_SHA2_192F,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 3,
        public_key_size: 48,
        private_key_size: 96,
        signature_size: Some(35664),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaSha2_256s,
        oid: oid::SLH_DSA_SHA2_256S,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 5,
        public_key_size: 64,
        private_key_size: 128,
        signature_size: Some(29792),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaSha2_256f,
        oid: oid::SLH_DSA_SHA2_256F,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 5,
        public_key_size: 64,
        private_key_size: 128,
        signature_size: Some(49856),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaShake128s,
        oid: oid::SLH_DSA_SHAKE_128S,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 1,
        public_key_size: 32,
        private_key_size: 64,
        signature_size: Some(7856),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaShake128f,
        oid: oid::SLH_DSA_SHAKE_128F,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 1,
        public_key_size: 32,
        private_key_size: 64,
        signature_size: Some(17088),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaShake192s,
        oid: oid::SLH_DSA_SHAKE_192S,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 3,
        public_key_size: 48,
        private_key_size: 96,
        signature_size: Some(16224),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaShake192f,
        oid: oid::SLH_DSA_SHAKE_192F,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 3,
        public_key_size: 48,
        private_key_size: 96,
        signature_size: Some(35664),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaShake256s,
        oid: oid::SLH_DSA_SHAKE_256S,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 5,
        public_key_size: 64,
        private_key_size: 128,
        signature_size: Some(29792),
        ciphertext_size: None,
    },
    AlgorithmInfo {
        name: AlgorithmName::SlhDsaShake256f,
        oid: oid::SLH_DSA_SHAKE_256F,
        algorithm_type: AlgorithmType::Sign,
        family: AlgorithmFamily::SlhDsa,
        security_level: 5,
        public_key_size: 64,
        private_key_size: 128,
        signature_size: Some(49856),
        ciphertext_size: None,
    },
];

pub fn get(name: AlgorithmName) -> &'static AlgorithmInfo {
    ALGORITHM_INFO
        .iter()
        .find(|info| info.name == name)
        .expect("All algorithm names should have info")
}

pub fn list() -> impl Iterator<Item = AlgorithmName> {
    AlgorithmName::all().iter().copied()
}

pub fn list_by_type(algorithm_type: AlgorithmType) -> impl Iterator<Item = AlgorithmName> {
    ALGORITHM_INFO
        .iter()
        .filter(move |info| info.algorithm_type == algorithm_type)
        .map(|info| info.name)
}

pub fn list_by_family(family: AlgorithmFamily) -> impl Iterator<Item = AlgorithmName> {
    ALGORITHM_INFO
        .iter()
        .filter(move |info| info.family == family)
        .map(|info| info.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get() {
        let info = get(AlgorithmName::MlKem512);
        assert_eq!(info.name, AlgorithmName::MlKem512);
        assert_eq!(info.oid, oid::ML_KEM_512);
        assert_eq!(info.algorithm_type, AlgorithmType::Kem);
        assert_eq!(info.family, AlgorithmFamily::MlKem);
        assert_eq!(info.security_level, 1);
        assert_eq!(info.public_key_size, 800);
        assert_eq!(info.private_key_size, 1632);
        assert_eq!(info.ciphertext_size, Some(768));
        assert_eq!(info.signature_size, None);
    }

    #[test]
    fn test_list() {
        let all: Vec<_> = list().collect();
        assert_eq!(all.len(), 18);
    }

    #[test]
    fn test_list_by_type_kem() {
        let kems: Vec<_> = list_by_type(AlgorithmType::Kem).collect();
        assert_eq!(kems.len(), 3);
        assert!(kems.contains(&AlgorithmName::MlKem512));
        assert!(kems.contains(&AlgorithmName::MlKem768));
        assert!(kems.contains(&AlgorithmName::MlKem1024));
    }

    #[test]
    fn test_list_by_type_sign() {
        let signs: Vec<_> = list_by_type(AlgorithmType::Sign).collect();
        assert_eq!(signs.len(), 15);
    }

    #[test]
    fn test_list_by_family() {
        let ml_kem: Vec<_> = list_by_family(AlgorithmFamily::MlKem).collect();
        assert_eq!(ml_kem.len(), 3);

        let ml_dsa: Vec<_> = list_by_family(AlgorithmFamily::MlDsa).collect();
        assert_eq!(ml_dsa.len(), 3);

        let slh_dsa: Vec<_> = list_by_family(AlgorithmFamily::SlhDsa).collect();
        assert_eq!(slh_dsa.len(), 12);
    }
}
