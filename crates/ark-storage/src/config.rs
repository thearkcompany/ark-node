#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Maximum size of block cache in megabytes (default: 32 MB)
    pub block_cache_mb: u32,
    /// Maximum size of write buffer / memtable in megabytes (default: 16 MB)
    pub write_buffer_mb: u32,
}

impl StorageConfig {
    /// Frugal defaults guaranteeing total engine memory footprint <= 64 MB
    pub fn frugal() -> Self {
        Self {
            block_cache_mb: 32,
            write_buffer_mb: 16,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::frugal()
    }
}
