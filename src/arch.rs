//! Architecture-agnostic traits and types for page table operations, enabling support for multiple CPU architectures.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use crate::{
    MemoryAttributes, PagingType, PtResult,
    structs::{PageLevel, PhysicalAddress, VirtualAddress},
};

pub(crate) trait PageTableHal {
    type PTE: PageTableEntry;
    const DEFAULT_ATTRIBUTES: MemoryAttributes;
    const MAX_ENTRIES: usize;

    /// SAFETY: This function is unsafe because it directly manipulates the page table memory at the given base address
    /// to zero it. The caller must ensure that the base address is valid and points to a page table that can be
    /// safely zeroed.
    unsafe fn zero_page(base: VirtualAddress);
    fn paging_type_supported(paging_type: PagingType) -> PtResult<()>;
    fn get_zero_va(paging_type: PagingType) -> PtResult<VirtualAddress>;
    fn invalidate_tlb(va: VirtualAddress);
    fn get_max_va(page_type: PagingType) -> PtResult<VirtualAddress>;
    fn is_table_active(base: u64) -> bool;
    /// SAFETY: This function is unsafe because it updates the HW page table registers to install a new page table.
    /// The caller must ensure that the base address is valid and points to a properly constructed page table.
    unsafe fn install_page_table(base: u64) -> PtResult<()>;
    fn level_supports_pa_entry(level: PageLevel) -> bool;
    fn get_self_mapped_base(level: PageLevel, va: VirtualAddress, paging_type: PagingType) -> u64;
}

pub(crate) trait PageTableEntry {
    fn update_fields(
        &mut self,
        attributes: MemoryAttributes,
        pa: PhysicalAddress,
        leaf_entry: bool,
        level: PageLevel,
        va: VirtualAddress,
    ) -> PtResult<()>;
    fn get_present_bit(&self) -> bool;
    fn set_present_bit(&mut self, value: bool, va: VirtualAddress);
    fn get_next_address(&self) -> PhysicalAddress;
    fn get_attributes(&self) -> MemoryAttributes;
    fn dump_entry_header();
    fn dump_entry(&self, va: VirtualAddress, level: PageLevel) -> PtResult<()>;
    fn points_to_pa(&self, level: PageLevel) -> bool;
    fn entry_ptr_address(&self) -> u64;
}
