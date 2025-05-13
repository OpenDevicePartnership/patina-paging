#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate alloc;
pub mod aarch64;
pub(crate) mod arch;
pub mod page_allocator;
pub(crate) mod paging;
pub(crate) mod structs;
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

    // The range specified contains some pages that are mapped and some that are unmapped
    InconsistentMappingAcrossRange,

    // Paging type not supported.
    UnsupportedPagingType,
}

#[derive(Debug, PartialEq)]
enum RangeMappingState {
    Uninitialized,
    Mapped(MemoryAttributes),
    Unmapped,
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

use page_allocator::PageAllocator;
use paging::PageTablesInternal;
use structs::PageLevel;

cfg_if::cfg_if! {
    // Do not optimize these sections. Maintainability and readability take
    // priority over everything else.
    if #[cfg(target_arch = "x86_64")] {
        type SystemArch = x64::PageTableX64;
    } else if #[cfg(target_arch = "aarch64")] {
        type SystemArch = aarch64::PageTableAarch64;
    } else {
        compile_error!("Unsupported architecture");
    }
}

pub struct PageTables<P: PageAllocator> {
    internal: PageTablesInternal<P, SystemArch>,
}

impl<P: PageAllocator> PageTables<P> {
    pub fn new(allocator: P, paging_type: PagingType) -> PtResult<Self> {
        let internal = PageTablesInternal::<P, SystemArch>::new(allocator, paging_type)?;
        Ok(Self { internal })
    }

    /// Create a page table from existing page table base. This can be used to
    /// parse or edit an existing identity mapped page table.
    ///
    /// # Safety
    ///
    /// This routine will return a struct that will parse memory addresses from
    /// PFNs in the provided base, so that caller is responsible for ensuring
    /// safety of that base.
    ///
    pub unsafe fn from_existing(base: u64, page_allocator: P, paging_type: PagingType) -> PtResult<Self> {
        let internal = PageTablesInternal::<P, SystemArch>::from_existing(base, page_allocator, paging_type)?;
        Ok(Self { internal })
    }

    /// Function to borrow the allocator from the page table instance.
    /// This is done this way to allow the page table to return a concrete
    /// type instead of the dyn ref. This is required to allow the page allocator to
    /// be managed by the caller, while the page table can still allocate pages from
    /// the allocator
    ///
    /// ## Returns
    /// * `&mut Self::ALLOCATOR` - Borrowed allocator
    pub fn borrow_allocator(&mut self) -> &mut P {
        self.internal.borrow_allocator()
    }

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
    pub fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        self.internal.map_memory_region(address, size, attributes)
    }

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
    pub fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()> {
        self.internal.unmap_memory_region(address, size)
    }

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
    pub fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        self.internal.remap_memory_region(address, size, attributes)
    }

    /// Function to install the page table from this page table instance.
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    pub fn install_page_table(&mut self) -> PtResult<()> {
        self.internal.install_page_table()
    }

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
    /// * Returns `Ok(MemoryAttributes)` if successful else `Err(PtError)` if failed
    pub fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes> {
        self.internal.query_memory_region(address, size)
    }

    /// Function to dump memory ranges with their attributes. It uses current
    /// cr3 as the base. This function can be used from
    /// `test_dump_page_tables()` test case
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    pub fn dump_page_tables(&self, address: u64, size: u64) {
        self.internal.dump_page_tables(address, size)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingType {
    Paging5Level,
    Paging4Level,
}

impl PagingType {
    pub(crate) fn root_level(self) -> PageLevel {
        match self {
            PagingType::Paging5Level => PageLevel::Level5,
            PagingType::Paging4Level => PageLevel::Level4,
        }
    }
}
