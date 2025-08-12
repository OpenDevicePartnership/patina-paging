//! Paging
//!
//! Implementation for identity mapped page table management for x64 and aarch64.
//! This library provides structures that allow building, installing, and editing
//! page tables in a no_std environment and without the use of Alloc.
//!
//! The [`PageTable`] trait provides the interface for managing page tables.
//! The caller must provide an implementation of the [`page_allocator::PageAllocator`]
//! trait which the page table implementation will use to allocate pages of physical
//! memory for use in the page tables.
//!
//! This crate currently contains two concrete implementations of the [`PageTable`]
//! trait: [`x64::X64PageTable`] and [`aarch64::AArch64PageTable`].
//!
//! ## Examples
//!
//! ``` rust
//! use patina_paging::{aarch64, x64, MemoryAttributes, PageTable, PagingType, PtResult};
//! use patina_paging::page_allocator::PageAllocator;
//!
//! struct MyPageAllocator;
//! impl PageAllocator for MyPageAllocator {
//!    fn allocate_page(&mut self, align: u64, size: u64, is_root: bool) -> PtResult<u64> {
//!       // Return page aligned address of the allocated page, or an error.
//!       Ok(0)
//!    }
//! }
//!
//! fn main_x64() -> PtResult<()> {
//!     // Create a X64 page table.
//!     let mut allocator = MyPageAllocator;
//!     let mut page_table = x64::X64PageTable::new(allocator, PagingType::Paging4Level)?;
//!
//!     // Map a memory region with read-only and write-back attributes.
//!     page_table.map_memory_region(0x1000, 0x2000, MemoryAttributes::ReadOnly | MemoryAttributes::Writeback)?;
//!
//!     // Install the page table.
//!     page_table.install_page_table()?;
//!     Ok(())
//! }
//!
//! fn main_aarch64() -> PtResult<()> {
//!     // Create a AArch64 page table.
//!     let mut allocator = MyPageAllocator;
//!     let mut page_table = aarch64::AArch64PageTable::new(allocator, PagingType::Paging4Level)?;
//!
//!     // Map a memory region with read-only and write-back attributes.
//!     page_table.map_memory_region(0x1000, 0x2000, MemoryAttributes::ReadOnly | MemoryAttributes::Writeback).unwrap();
//!
//!     // Install the page table.
//!     page_table.install_page_table()?;
//!     Ok(())
//! }
//! ```
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

#![cfg_attr(not(test), no_std)]
#![feature(coverage_attribute)]

pub mod aarch64;
pub(crate) mod arch;
pub mod page_allocator;
pub(crate) mod paging;
pub(crate) mod structs;
#[cfg(test)]
#[coverage(off)]
mod tests;
pub mod x64;
use bitflags::bitflags;

pub type PtResult<T> = Result<T, PtError>;

/// Paging error codes. These are used to indicate errors that occur during
/// paging operations. The errors are returned as a `Result` type, where
/// `Ok(T)` indicates success and `Err(PtError)` indicates an error.
#[derive(Debug, PartialEq)]
pub enum PtError {
    /// Invalid parameter.
    InvalidParameter,

    /// Out of resources. Usually indicating that the page allocator ran out of
    /// memory.
    OutOfResources,

    /// No mapping exists for the entire range.
    NoMapping,

    /// The memory range is mapped with different attributes.
    IncompatibleMemoryAttributes,

    /// Provided base address is not aligned to the page size.
    UnalignedPageBase,

    /// The provided address is not aligned to the page size.
    UnalignedAddress,

    /// The provided size is not aligned to the page size.
    UnalignedMemoryRange,

    /// A memory range is not valid.
    InvalidMemoryRange,

    /// The range specified contains some pages that are mapped and some that are unmapped.
    InconsistentMappingAcrossRange,

    /// Paging type not supported by this implementation.
    UnsupportedPagingType,

    /// The base address and range would cause an overflow when performing page table operations.
    AdditionOverflow,

    /// The base address and range would cause an underflow when performing page table operations.
    SubtractionUnderflow,
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

/// PageTable trait is implemented by all concrete page table implementations
/// and provides the interface for managing page tables.
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
    fn install_page_table(&mut self) -> PtResult<()>;

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
    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes>;

    /// Function to dump memory ranges with their attributes. It uses current
    /// cr3 as the base. This function can be used from
    /// `test_dump_page_tables()` test case
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    fn dump_page_tables(&self, address: u64, size: u64) -> PtResult<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingType {
    // 5-level paging, only supported on x64.
    Paging5Level,
    // 4-level paging.
    Paging4Level,
}

impl PagingType {
    /// Gets the numbers of bits used for linear address space in this paging type.
    pub(crate) const fn linear_address_bits(self) -> u64 {
        match self {
            PagingType::Paging5Level => 57,
            PagingType::Paging4Level => 48,
        }
    }
}
