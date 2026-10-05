//! [Preparação para v1.0] Cauchy RS 10+4 e Safe-Ghost Locking.

pub struct CauchyReedSolomon {
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl Default for CauchyReedSolomon {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 4,
        }
    }
}
