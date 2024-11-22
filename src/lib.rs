#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;
pub mod aarch64;
pub mod page_allocator;
pub mod x64;
use bitflags::bitflags;

pub type PtResult<T> = Result<T, PtError>;

#[derive(Debug, PartialEq)]
pub enum PtError {
    // Invalid parameter
    InvalidParameter,

    // Out of resources
    OutOfResources,

    // No Mapping
    NoMapping,

    // Incompatible Memory Attributes
    IncompatibleMemoryAttributes,

    // Unaligned Page Base
    UnalignedPageBase,

    // Unaligned Address
    UnalignedAddress,

    // Unaligned Memory Range
    UnalignedMemoryRange,

    // Invalid Memory Range
    InvalidMemoryRange,
}

// NOTE: On X64, Memory caching attributes are handled via MTRRs. On AArch64,
// paging handles both memory access and caching attributes. Hence we defined
// both of them here.
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MemoryAttributes: u64 {
        // Memory Caching Attributes
        const Uncacheable       = 0x00000000_00000001u64;
        const WriteCombining    = 0x00000000_00000002u64;
        const WriteThrough      = 0x00000000_00000004u64;
        const Writeback         = 0x00000000_00000008u64;
        const UncacheableExport = 0x00000000_00000010u64;
        const WriteProtect      = 0x00000000_00001000u64;

        // Memory Access Attributes
        const ReadProtect       = 0x00000000_00002000u64;   // Maps to Present bit on X64
        const ExecuteProtect    = 0x00000000_00004000u64;   // Maps to NX bit on X64
        const ReadOnly          = 0x00000000_00020000u64;   // Maps to Read/Write bit on X64


        const CacheAttributesMask = Self::Uncacheable.bits() |
                                   Self::WriteCombining.bits() |
                                   Self::WriteThrough.bits() |
                                   Self::Writeback.bits() |
                                   Self::UncacheableExport.bits() |
                                   Self::WriteProtect.bits();

        const AccessAttributesMask = Self::ReadProtect.bits() |
                                    Self::ExecuteProtect.bits() |
                                    Self::ReadOnly.bits();
    }
}

pub trait PageTable {
    /// Function to map the designated memory region to with provided
    /// attributes.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    /// * `attributes` - The memory attributes to map. The acceptable
    ///   input will be ExecuteProtect, ReadOnly, as well as Uncacheable,
    ///   WriteCombining, WriteThrough, Writeback, UncacheableExport
    ///   Compatible attributes can be "Ored"
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()>;

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
    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()>;

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
    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PagingType {
    Paging4KB5Level,
    Paging4KB4Level,
    AArch64PageTable4KB,
}

#[cfg(test)]
mod tests;
