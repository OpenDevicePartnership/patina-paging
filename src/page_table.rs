use crate::page_table_error::PtResult;
#[cfg(any(target_arch = "aarch64", test))]
pub(crate) mod arm64;
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) mod x64;

// Cache attributes

//
// For X64:
// .-----------------.------.-----.-----.-----.-----.
// |                 | UC   | WC  | WP  | WT  | WB  |
// + --------------- + ---  + --- + --- + --- + --- +
// | Read  Cacheable | no   | no  | yes | yes | yes |
// | Write Cacheable | no   | no* | no  | yes | yes |
// '-----------------'------'-----'-----'-----'-----'
//
// NOTE: All caching attributes for x64 are handled via MTRRs, So below
// attributes are not expected to be used in x64 paging implementation. They are
// left here mainly for ARM64 implementation(which does not have MTRRs).
//
// Cache attributes(sorted from not so cache friendly to cache friendly)
pub const EFI_MEMORY_UC: u64 = 0x00000000_00000001u64;
pub const EFI_MEMORY_WC: u64 = 0x00000000_00000002u64;
pub const EFI_MEMORY_WP: u64 = 0x00000000_00001000u64;
pub const EFI_MEMORY_WT: u64 = 0x00000000_00000004u64;
pub const EFI_MEMORY_WB: u64 = 0x00000000_00000008u64;
pub const EFI_MEMORY_UCE: u64 = 0x00000000_00000010u64;

// Memory access attributes
pub const EFI_MEMORY_RP: u64 = 0x00000000_00002000u64;
pub const EFI_MEMORY_XP: u64 = 0x00000000_00004000u64;
pub const EFI_MEMORY_RO: u64 = 0x00000000_00020000u64;

pub const EFI_MEMORY_SP: u64 = 0x00000000_00040000u64;
pub const EFI_MEMORY_CPU_CRYPTO: u64 = 0x00000000_00080000u64;
pub const EFI_CACHE_ATTRIBUTE_MASK: u64 =
    EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB | EFI_MEMORY_UCE | EFI_MEMORY_WP;
pub const EFI_MEMORY_ACCESS_MASK: u64 = EFI_MEMORY_RP | EFI_MEMORY_XP | EFI_MEMORY_RO;

pub trait PageTable {
    /// Function to map the designated memory region to with provided
    /// attributes.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    /// * `attributes` - The memory attributes to map. The acceptable
    ///   input will be EFI_MEMORY_XP, EFI_MEMORY_RO, as well as EFI_MEMORY_UC,
    ///   EFI_MEMORY_WC, EFI_MEMORY_WT, EFI_MEMORY_WB, EFI_MEMORY_UCE
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> PtResult<()>;

    /// Function to unmap the memory region provided by the caller. The
    /// requested memory region must be fully mapped prior to this call. Unlike
    /// remap_memory_region, the entire region does not have to possess the same
    /// attribute for this operation.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()>;

    /// Function to remap the memory region provided by the caller. The memory
    /// provided has to be previously mapped and has the same memory attributes
    /// for the entire memory region.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    /// * `attributes` - The memory attributes to map.
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> PtResult<()>;

    /// Function to install the page table from this page table instance.
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn install_page_table(&self) -> PtResult<()>;

    /// Function to query the mapping status and return attribute of supplied
    /// memory region if it is properly and consistently mapped.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    ///
    /// ## Returns
    /// Returns memory attributes
    ///
    /// ## Errors
    /// * Returns `Ok(u64)` if successful else `Err(PtError)` if failed
    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<u64>;
}
