//! Data structures and constants for x64 page table entries and address translation.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use crate::{
    MemoryAttributes, PtError,
    structs::{PageLevel, PhysicalAddress, VirtualAddress},
    x64::{PD, PDP, PML4, PML5, PT, invalidate_tlb},
};
use bitfield_struct::bitfield;
use core::ptr::write_volatile;

// The following definitions are the maximum virtual address for each level of the page table hierarchy. These are
// above the range generally supported by processors, but we only care that our zero VA and self-map aren't overwritten
pub(crate) const MAX_VA_5_LEVEL: u64 = 0xFFFD_FFFF_FFFF_FFFF;
pub(crate) const MAX_VA_4_LEVEL: u64 = 0xFFFF_FEFF_FFFF_FFFF;

// The following definitions are the zero VA for each level of the page table hierarchy. These are used to create a
// VA range that is used to zero pages before putting them in the page table. These addresses are calculated as the
// first VA in the penultimate index in the top level page table.
pub(crate) const ZERO_VA_5_LEVEL: u64 = 0xFFFE_0000_0000_0000;
pub(crate) const ZERO_VA_4_LEVEL: u64 = 0xFFFF_FF00_0000_0000;

// The following definitions are the address within the self map that points to that level of the page table
// given the overall paging scheme, 4 vs 5 level. This is determined by choosing the self map index for each
// level need to recurse into the self map, e.g. the top level entry is 0xFFFF_FFFF_FFFF_F000 because it is index
// 0x1FF for each level of the hierarchy and is in canonical form (e.g. bits 63:48 match bit 47).
pub(crate) const FIVE_LEVEL_PML5_SELF_MAP_BASE: u64 = 0xFFFF_FFFF_FFFF_F000;
pub(crate) const FIVE_LEVEL_PML4_SELF_MAP_BASE: u64 = 0xFFFF_FFFF_FFE0_0000;
pub(crate) const FIVE_LEVEL_PDP_SELF_MAP_BASE: u64 = 0xFFFF_FFFF_C000_0000;
pub(crate) const FIVE_LEVEL_PD_SELF_MAP_BASE: u64 = 0xFFFF_FF80_0000_0000;
pub(crate) const FIVE_LEVEL_PT_SELF_MAP_BASE: u64 = 0xFFFF_0000_0000_0000;

pub(crate) const FOUR_LEVEL_PML4_SELF_MAP_BASE: u64 = 0xFFFF_FFFF_FFFF_F000;
pub(crate) const FOUR_LEVEL_PDP_SELF_MAP_BASE: u64 = 0xFFFF_FFFF_FFE0_0000;
pub(crate) const FOUR_LEVEL_PD_SELF_MAP_BASE: u64 = 0xFFFF_FFFF_C000_0000;
pub(crate) const FOUR_LEVEL_PT_SELF_MAP_BASE: u64 = 0xFFFF_FF80_0000_0000;

pub(crate) const CR3_PAGE_BASE_ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000; // 40 bit - lower 12 bits for alignment

pub(crate) const PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT: u64 = 12u64; // lower 12 bits for alignment
pub(crate) const PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000; // 40 bit - lower 12 bits for alignment

#[rustfmt::skip]
#[bitfield(u64)]
pub struct PageTableEntryX64 {
    pub present: bool,                // 1 bit -  0 = Not present in memory, 1 = Present in memory
    pub read_write: bool,             // 1 bit -  0 = Read-Only, 1= Read/Write
    pub user_supervisor: bool,        // 1 bit -  0 = Supervisor, 1=User
    pub write_through: bool,          // 1 bit -  0 = Write-Back caching, 1=Write-Through caching
    pub cache_disabled: bool,         // 1 bit -  0 = Cached, 1=Non-Cached
    pub accessed: bool,               // 1 bit -  0 = Not accessed, 1 = Accessed (set by CPU)
    pub dirty: bool,                  // 1 bit -  0 = Not Dirty, 1 = written by processor on access to page
    pub page_size: bool,              // 1 bit -  1 = 2MB page for PD, 1GB page for PDP, Must be 0 for others.
    pub global: bool,                 // 1 bit -  0 = Not global page, 1 = global page TLB not cleared on CR3 write
    #[bits(3)]
    pub available: u8,                // 3 bits -  Available for use by system software
    #[bits(40)]
    pub page_table_base_address: u64, // 40 bits -  Page Table Base Address
    #[bits(11)]
    pub available_high: u16,          // 11 bits -  Available for use by system software
    pub nx: bool,                     // 1 bit -  0 = Execute Code, 1 = No Code Execution
}

impl PageTableEntryX64 {
    /// set all the memory attributes for the current entry
    fn set_attributes(&mut self, attributes: MemoryAttributes) {
        if attributes.contains(MemoryAttributes::ReadProtect) {
            self.set_present(false);
        } else {
            self.set_present(true);
        }

        if attributes.contains(MemoryAttributes::ReadOnly) {
            self.set_read_write(false);
        } else {
            self.set_read_write(true);
        }

        self.set_user_supervisor(true);
        self.set_write_through(false);
        self.set_cache_disabled(false);
        self.set_page_size(false);
        self.set_global(false);
        self.set_available(0);
        self.set_available_high(0);

        if attributes.contains(MemoryAttributes::ExecuteProtect) {
            self.set_nx(true);
        } else {
            self.set_nx(false);
        }
    }

    /// return the 40 bits table base address converted to canonical address
    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        let mut page_table_base_address = self.page_table_base_address();

        page_table_base_address <<= PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT;

        page_table_base_address.into()
    }

    /// Performs an overwrite of the table entry. This ensures that all fields
    /// are written to memory at once to avoid partial PTE edits causing unexpected
    /// behavior with speculative execution or when operating on the current mapping.
    pub fn swap(&mut self, other: &Self) {
        // Safety: This is safe because we are writing to a valid memory location that is owned by this struct and we
        // are not mutating the memory location in a way that would cause undefined behavior. We are simply overwriting
        // the entire entry atomically.
        unsafe { write_volatile(&mut self.0, other.0) };
    }
}

impl crate::arch::PageTableEntry for PageTableEntryX64 {
    /// update all the fields and next table base address
    fn update_fields(
        &mut self,
        attributes: MemoryAttributes,
        pa: PhysicalAddress,
        leaf_entry: bool,
        level: PageLevel,
        va: VirtualAddress,
    ) -> Result<(), PtError> {
        // ensure break-before-make by working on a copy and then swapping. PageTableEntryX64 derives Copy, so this
        // will create a copy of the entry to modify
        let mut copy = *self;

        let mut next_level_table_base: u64 = pa.into();

        next_level_table_base &= PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_MASK;
        next_level_table_base >>= PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT;

        copy.set_page_table_base_address(next_level_table_base);
        copy.set_present(true);

        // update the memory attributes irrespective of new or old page table
        copy.set_attributes(attributes);

        // update page size if we have a large page. set_attributes will have cleared this bit.
        if matches!(level, PD | PDP) {
            let page_size = leaf_entry && !attributes.contains(MemoryAttributes::ReadProtect);
            copy.set_page_size(page_size);
        }

        let prev_valid = self.present();
        self.swap(&copy);
        if prev_valid {
            invalidate_tlb(va);
        }
        Ok(())
    }

    fn get_present_bit(&self) -> bool {
        self.present()
    }

    fn set_present_bit(&mut self, value: bool, va: VirtualAddress) {
        // PageTableEntryX64 is Copy, so we can make a copy to modify and then swap it in
        let mut copy = *self;
        copy.set_present(value);
        let prev_valid = self.present();
        self.swap(&copy);
        if prev_valid {
            invalidate_tlb(va);
        }
    }

    fn get_next_address(&self) -> PhysicalAddress {
        self.get_canonical_page_table_base()
    }

    /// return all the memory attributes for the current entry
    fn get_attributes(&self) -> MemoryAttributes {
        let mut attributes = MemoryAttributes::empty();

        if !self.present() {
            attributes |= MemoryAttributes::ReadProtect;
        }

        if !self.read_write() {
            attributes |= MemoryAttributes::ReadOnly;
        }

        if self.nx() {
            attributes |= MemoryAttributes::ExecuteProtect;
        }

        attributes
    }

    fn dump_entry(&self, va: VirtualAddress, level: PageLevel) -> Result<(), PtError> {
        let nx = self.nx() as u64;
        let available_high = self.available_high() as u64;
        let page_table_base_address = self.page_table_base_address();
        let available = self.available() as u64;
        let global = self.global() as u64;
        let pat = self.page_size() as u64;
        let dirty = self.dirty() as u64;
        let accessed = self.accessed() as u64;
        let cache_disabled = self.cache_disabled() as u64;
        let write_through = self.write_through() as u64;
        let user_supervisor = self.user_supervisor() as u64;
        let read_write = self.read_write() as u64;
        let present = self.present() as u64;
        let depth = 2 * level.depth();
        let inv_depth = 8 - depth;
        let level_name = match level {
            PT => "PT",
            PD => "PD",
            PDP => "PDP",
            PML4 => "PML4",
            PML5 => "PML5",
        };

        log::info!(
            "{:6}|{:depth$}[{} {}]{:inv_depth$}|{:01b}|{:011b}|{:040b}|{:03b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|",
            level_name,
            "",
            va,
            ((va + level.entry_va_size())? - 1)?,
            "",
            nx,                      // 1 bit -  0 = Execute Code, 1 = No Code Execution
            available_high & 0x7FF,  // 11 bits -  Available for use by system software
            page_table_base_address, // 40 bits -  Page Table Base Address
            available & 0x7,         // 3 bits -  Available for use by system software
            global,                  // 1 bit -  0 = Not global page, 1 = global page TLB not cleared on CR3 write
            pat,                     // 1 bit
            dirty,                   // 1 bit -  0 = Not Dirty, 1 = written by processor on access to page
            accessed,                // 1 bit -  0 = Not accessed, 1 = Accessed (set by CPU)
            cache_disabled,          // 1 bit -  0 = Cached, 1=Non-Cached
            write_through,           // 1 bit -  0 = Write-Back caching, 1=Write-Through caching
            user_supervisor,         // 1 bit -  0 = Supervisor, 1=User
            read_write,              // 1 bit -  0 = Read-Only, 1= Read/Write
            present,                 // 1 bit -  0 = Not present in memory, 1 = Present in memory
            depth = depth,
            inv_depth = inv_depth,
        );

        Ok(())
    }

    fn dump_entry_header() {
        log::info!(
            "------------------------------------------------------------------------------------------------------------------------------------"
        );
        log::info!(
            "                                                      63 62       52 51                                   12 11 9 8 7 6 5 4 3 2 1 0 "
        );
        log::info!(
            "                                                      |N|           |                                        |   |M|P|I| |P|P|U|R| |"
        );
        log::info!(
            "                                                      |X| Available |     Page-Map Level-4 Base Address      |AVL|B|G|G|A|C|W|/|/|P|"
        );
        log::info!(
            "                                                      | |           |                                        |   |Z|S|N| |D|T|S|W| |"
        );
        log::info!(
            "------------------------------------------------------------------------------------------------------------------------------------"
        );
    }

    fn points_to_pa(&self, level: PageLevel) -> bool {
        match level {
            PT => true,
            PD | PDP => self.page_size(),
            _ => false,
        }
    }

    fn entry_ptr_address(&self) -> u64 {
        self as *const _ as u64
    }

    fn unmap(&mut self, va: VirtualAddress) {
        // PageTableEntryX64 is Copy, so we can make a copy to modify and then swap it in
        let mut copy = *self;
        copy.0 = 0;
        let prev_valid = self.present();
        self.swap(&copy);
        if prev_valid {
            invalidate_tlb(va);
        }
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use crate::{
        MemoryAttributes,
        arch::PageTableEntry,
        structs::{PageLevel, PhysicalAddress, VirtualAddress},
    };

    #[test]
    fn test_update_fields_sets_present_and_base_address() {
        let mut entry = PageTableEntryX64::new();
        let pa = PhysicalAddress::from(0x1234_5678_9000u64);
        let attrs = MemoryAttributes::ExecuteProtect | MemoryAttributes::ReadOnly;

        entry.update_fields(attrs, pa, true, PageLevel::Level1, pa.into()).unwrap();

        assert!(entry.present());
        assert_eq!(
            entry.page_table_base_address() << PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT,
            0x1234_5678_9000u64
        );
        assert_eq!(entry.get_attributes(), attrs);
    }

    #[test]
    fn test_set_and_get_attributes() {
        let mut entry = PageTableEntryX64::new();

        // Test ReadProtect
        entry.set_attributes(MemoryAttributes::ReadProtect);
        assert!(!entry.present());
        assert!(entry.get_attributes().contains(MemoryAttributes::ReadProtect));

        // Test ReadOnly
        entry.set_attributes(MemoryAttributes::ReadOnly);
        assert!(!entry.read_write());
        assert!(entry.get_attributes().contains(MemoryAttributes::ReadOnly));

        // Test ExecuteProtect
        entry.set_attributes(MemoryAttributes::ExecuteProtect);
        assert!(entry.nx());
        assert!(entry.get_attributes().contains(MemoryAttributes::ExecuteProtect));

        // Test combination
        let mut attrs = MemoryAttributes::empty();
        attrs |= MemoryAttributes::ReadOnly | MemoryAttributes::ExecuteProtect;
        entry.set_attributes(attrs);
        assert!(!entry.read_write());
        assert!(entry.nx());
    }

    #[test]
    fn test_get_canonical_page_table_base() {
        let mut entry = PageTableEntryX64::new();
        let pa: u64 = PhysicalAddress::from(0xABC0_0000_0000u64).into();
        entry.set_page_table_base_address(pa >> PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT);

        let result: u64 = entry.get_canonical_page_table_base().into();
        assert_eq!(result, 0xABC0_0000_0000u64);
    }

    #[test]
    fn test_swap_overwrites_entry() {
        let mut entry1 = PageTableEntryX64::new();
        let mut entry2 = PageTableEntryX64::new();

        entry1.set_present(true);
        entry1.set_read_write(true);
        entry2.set_present(false);
        entry2.set_read_write(false);

        entry1.swap(&entry2);

        assert_eq!(entry1.present(), entry2.present());
        assert_eq!(entry1.read_write(), entry2.read_write());
    }

    #[test]
    fn test_dump_entry_runs() {
        let mut entry = PageTableEntryX64::new();
        entry.set_present(true);
        entry.set_read_write(true);
        let va = VirtualAddress::from(0x1000u64);
        let level = PageLevel::Level1;
        // Should not panic or error
        let _ = entry.dump_entry(va, level);
    }
}
