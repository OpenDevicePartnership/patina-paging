//! Architecture-agnostic traits and types for page table operations, enabling support for multiple CPU architectures.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use crate::{
    MemoryAttributes, PagingType, PtError,
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
    fn paging_type_supported(paging_type: PagingType) -> Result<(), PtError>;
    fn get_zero_va(paging_type: PagingType) -> Result<VirtualAddress, PtError>;
    fn invalidate_tlb(va: VirtualAddress);
    fn invalidate_tlb_all();
    fn get_max_va(page_type: PagingType) -> Result<VirtualAddress, PtError>;
    fn is_table_active(base: u64) -> bool;
    /// SAFETY: This function is unsafe because it updates the HW page table registers to install a new page table.
    /// The caller must ensure that the base address is valid and points to a properly constructed page table.
    unsafe fn install_page_table(base: u64) -> Result<(), PtError>;
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
    ) -> Result<(), PtError>;
    fn get_present_bit(&self) -> bool;
    fn set_present_bit(&mut self, value: bool, va: VirtualAddress);
    fn get_next_address(&self) -> PhysicalAddress;
    fn get_attributes(&self) -> MemoryAttributes;

    /// Returns the access attributes that non-leaf (table) entries impose on
    /// their children. On architectures where every level uses the same access
    /// bits (x86_64), the default — delegating to [`get_attributes`] — is
    /// correct.  On architectures with separate hierarchical fields (AArch64
    /// `ap_table`/`uxn_table`/`pxn_table`), this must be overridden to read
    /// those fields instead.
    fn get_inheritable_attributes(&self) -> MemoryAttributes {
        self.get_attributes()
    }

    fn dump_entry_header();
    fn dump_entry(&self, va: VirtualAddress, level: PageLevel) -> Result<(), PtError>;
    fn points_to_pa(&self, level: PageLevel) -> bool;
    fn entry_ptr_address(&self) -> u64;
    fn unmap(&mut self, va: VirtualAddress);
}
