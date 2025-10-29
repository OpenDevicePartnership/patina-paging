//! Data structures and constants for AArch64 page table entries and address translation.
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
};
use bitfield_struct::bitfield;

#[cfg(all(not(test), target_arch = "aarch64"))]
use crate::arch::PageTableEntry;

// This is the maximum virtual address that can be used in the system because of our artificial restriction to use
// the zero VA and self map index in the top level page table. This is a temporary restriction
pub(crate) const MAX_VA_4_LEVEL: u64 = 0x0000_FEFF_FFFF_FFFF;

const PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT: u64 = 12u64; // lower 12 bits for alignment

// The zero VA used to create a VA range to zero pages before putting them in the page table. These addresses are
// calculated as the first VA in the penultimate index in the top level page table.
pub(crate) const ZERO_VA_4_LEVEL: u64 = 0xFF00_0000_0000;

// The following definitions are the address within the self map that points to that level of the page table
// given the overall paging scheme, which is only 4 level for aarch64. This is determined by choosing the self map
// index for each level need to recurse into the self map, e.g. the top level entry is 0xFFFF_FFFF_F000 because it is
// index 0x1FF for each level of the hierarchy.
// N.B. These addresses are different for AARCH64 than X64 because there are two page table roots on AARCH64, TTBR0 and
// TTBR1. Bits 63:48 of the VA are used to select the root, so the self map must be at the top of the address space that
// corresponds to TTBR0, as that is the only root that this crate currently uses. However, this limits the address range
// supported by this crate as we steal the last two entries in the top level page table for the zero VA and the self
// map. The crate explicitly panics if such high level addresses are used, but this will be fixed in a future version
// of this crate so as not to artificially limit the address range lower than what is physically addressable by the
// CPU.
pub(crate) const FOUR_LEVEL_LEVEL4_SELF_MAP_BASE: u64 = 0xFFFF_FFFF_F000;
pub(crate) const FOUR_LEVEL_LEVEL3_SELF_MAP_BASE: u64 = 0xFFFF_FFE0_0000;
pub(crate) const FOUR_LEVEL_LEVEL2_SELF_MAP_BASE: u64 = 0xFFFF_C000_0000;
pub(crate) const FOUR_LEVEL_LEVEL1_SELF_MAP_BASE: u64 = 0xFF80_0000_0000;

// Below is a common definition for the AArch64 VMSAv8-64 stage-1 decriptors. This uses
// the common understanding of bits accross all levels/types to simplify translation
// as well as to allow for recursive translation.
#[rustfmt::skip]
#[bitfield(u64)]
pub struct PageTableEntryAArch64 {
    pub valid: bool,              // 1 bit -  Valid descriptor
    pub table_desc: bool,         // 1 bit -  Table descriptor, 1 = Table descriptor for look up level 0, 1, 2
    #[bits(3)]
    pub attribute_index: u8,      // 3 bits -  Used for caching attributes
    pub non_secure: bool,         // 1 bit  -  Non-secure
    #[bits(2)]
    pub access_permission: u8,    // 2 bits -  Access permissions
    #[bits(2)]
    pub shareable: u8,            // 2 bits -  SH 0 = Non-shareable, 2 = Outer Shareable, 3 = Inner Shareable
    pub access_flag: bool,        // 1 bit  -  Access flag
    pub not_global: bool,         // 1 bit  -  Not global
    #[bits(38)]
    pub page_frame_number: u64,   // 38 bits - Page frame number
    pub guarded_page: bool,       // 1 bit  -  Guarded page
    pub dirty_bit_modifier: bool, // 1 bit  -  DBM
    pub contiguous: bool,         // 1 bit  -  Contiguous
    pub pxn: bool,                // 1 bit  -  Privileged execute never
    pub uxn: bool,                // 1 bit  -  User execute never
    #[bits(4)]
    pub reserved0: u8,            // 4 bits -  Reserved for software use
    pub pxn_table: bool,           // 1 bit  -  Hierarchical permissions.
    pub uxn_table: bool,           // 1 bit  -  Hierarchical permissions.
    #[bits(2)]
    pub ap_table: u8,              // 2 bits -  Hierarchical permissions.
    pub ns_table: bool,            // 1 bit  -  Secure state, only for accessing in Secure IPA or PA space.
}

impl PageTableEntryAArch64 {
    pub fn is_valid_table(&self) -> bool {
        self.valid() && self.table_desc()
    }

    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        // This logic will need to be specialized if 16Kb or 64Kb granules are used.
        (self.page_frame_number() << PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT).into()
    }

    cfg_if::cfg_if! {
        if #[cfg(all(not(test), target_arch = "aarch64"))] {
            fn swap_entry(&mut self, new_entry: u64, va: u64) {
                // SAFETY: inline asm is inherently unsafe because Rust can't reason about it.
                // In this case we are replacing a live translation entry, which is a safe operation as long as the
                // caller ensures that the entry being replaced is valid.
                unsafe {
                    crate::aarch64::reg::replace_live_xlat_entry(self.entry_ptr_address(), new_entry, va);
                }
            }
        } else {
            // for testing, just set the entry directly
            fn swap_entry(&mut self, new_entry: u64, _va: u64) {
                self.0 = new_entry;
            }
        }
    }

    fn set_attributes(&mut self, attributes: MemoryAttributes) -> Result<(), PtError> {
        // This change pretty much follows the GcdAttributeToPageAttribute
        match attributes & MemoryAttributes::CacheAttributesMask {
            MemoryAttributes::Uncacheable => {
                self.set_attribute_index(0);
                self.set_shareable(0);
            }
            MemoryAttributes::WriteCombining => {
                self.set_attribute_index(1);
                self.set_shareable(0);
            }
            MemoryAttributes::WriteThrough => {
                self.set_attribute_index(2);
                self.set_shareable(3);
            }
            MemoryAttributes::Writeback => {
                self.set_attribute_index(3);
                self.set_shareable(3);
            }
            _ => {
                log::error!("Invalid memory attributes: {attributes:?}");
                return Err(PtError::InvalidParameter);
            }
        }

        if attributes.contains(MemoryAttributes::ExecuteProtect) {
            // TODO: need to check if the system in EL2 or EL1
            self.set_uxn(true);
            self.set_pxn(false);
        } else if !attributes.contains(MemoryAttributes::ExecuteProtect) {
            self.set_uxn(false);
            self.set_pxn(false);
        }

        if attributes.contains(MemoryAttributes::ReadOnly) {
            self.set_access_permission(2);
        } else {
            self.set_access_permission(0);
        }

        if attributes.contains(MemoryAttributes::ReadProtect) {
            self.set_valid(false);
        } else {
            self.set_valid(true);
            self.set_access_flag(true);
        }
        Ok(())
    }
}

impl crate::arch::PageTableEntry for PageTableEntryAArch64 {
    /// update all the fields and table base address
    fn update_fields(
        &mut self,
        attributes: MemoryAttributes,
        pa: PhysicalAddress,
        block: bool,
        level: PageLevel,
        va: VirtualAddress,
    ) -> Result<(), PtError> {
        if !pa.is_page_aligned() {
            return Err(PtError::UnalignedPageBase);
        }

        // PageTableEntryAArch64 is Copy, so we can make a copy to modify and then swap it in
        let mut copy = *self;

        let next_level_table_base: u64 = pa.into();
        let pfn = next_level_table_base >> PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT;
        copy.set_page_frame_number(pfn);

        copy.set_valid(true);

        // update the memory attributes irrespective of new or old page table
        copy.set_attributes(attributes)?;

        // set_attributes sets that this is a block entry, so we need to
        // set this if we are a table entry
        copy.set_table_desc(level == PageLevel::Level1 || !block);
        self.swap_entry(copy.0, va.into());

        // TODO: need to flush the cache if operating on the active page table
        Ok(())
    }

    fn get_present_bit(&self) -> bool {
        self.valid()
    }

    fn get_next_address(&self) -> PhysicalAddress {
        self.get_canonical_page_table_base()
    }

    fn entry_ptr_address(&self) -> u64 {
        self as *const _ as u64
    }

    /// return all the memory attributes for the current entry
    fn get_attributes(&self) -> MemoryAttributes {
        let mut attributes = MemoryAttributes::empty();

        if !self.valid() {
            attributes = MemoryAttributes::ReadProtect;
        } else {
            match self.attribute_index() {
                0 => attributes |= MemoryAttributes::Uncacheable,
                1 => attributes |= MemoryAttributes::WriteCombining,
                2 => attributes |= MemoryAttributes::WriteThrough,
                3 => attributes |= MemoryAttributes::Writeback,
                _ => attributes |= MemoryAttributes::Uncacheable,
            }

            if self.access_permission() == 2 {
                attributes |= MemoryAttributes::ReadOnly;
            }

            if self.uxn() {
                attributes |= MemoryAttributes::ExecuteProtect;
            }
        }

        // TODO: add other attributes
        attributes
    }

    fn set_present_bit(&mut self, value: bool, va: VirtualAddress) {
        // PageTableEntryAArch64 is Copy, so we can make a copy to modify and then swap it in
        let mut entry = *self;
        entry.set_valid(value);
        self.swap_entry(entry.0, va.into());
    }

    fn points_to_pa(&self, level: PageLevel) -> bool {
        match level {
            PageLevel::Level1 => true,
            PageLevel::Level2 | PageLevel::Level3 => !self.table_desc(),
            _ => false,
        }
    }

    fn dump_entry_header() {
        log::info!(
            "----------------------------------------------------------------------------------------------------------------------------------"
        );
    }

    fn dump_entry(&self, va: VirtualAddress, level: PageLevel) -> Result<(), PtError> {
        let valid = self.valid() as u64;
        let table_desc = self.table_desc() as u64;
        let attribute_index = self.attribute_index();
        let non_secure = self.non_secure() as u64;
        let access_permission = self.access_permission() as u64;
        let shareable = self.shareable();
        let access_flag = self.access_flag() as u64;
        let not_global = self.not_global() as u64;
        let page_frame_number = self.page_frame_number();
        let guarded_page = self.guarded_page() as u64;
        let dirty_bit_modifier = self.dirty_bit_modifier() as u64;
        let contiguous = self.contiguous() as u64;
        let pxn = self.pxn() as u64;
        let uxn = self.uxn() as u64;
        let reserved0 = self.reserved0();
        let pxn_table = self.pxn_table() as u64;
        let uxn_table = self.uxn_table() as u64;
        let ap_table = self.ap_table();
        let ns_table = self.ns_table() as u64;
        let depth = 2 * level.depth();
        let inv_depth = 8 - depth;
        let level_name = match level {
            PageLevel::Level5 => "INVD",
            PageLevel::Level4 => "LVL0",
            PageLevel::Level3 => "LVL1",
            PageLevel::Level2 => "LVL2",
            PageLevel::Level1 => "LVL3",
        };

        log::info!(
            "{:6}|{:depth$}[{} {}]{:inv_depth$}|{:01b}|{:02b}|{:01b}|{:01b}|{:04b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:038b}|{:01b}|{:01b}|{:02b}|{:02b}|{:01b}|{:03b}|{:01b}|{:01b}|",
            level_name,
            "",
            va,
            ((va + level.entry_va_size())? - 1)?,
            "",
            ns_table,           // 1 bit  -  Secure state, only for accessing in Secure IPA or PA space.
            ap_table,           // 2 bits -  Hierarchical permissions.
            uxn_table,          // 1 bit  -  Hierarchical permissions.
            pxn_table,          // 1 bit  -  Hierarchical permissions.
            reserved0,          // 4 bits -  Reserved for software use
            uxn,                // 1 bit  -  User execute never
            pxn,                // 1 bit  -  Privileged execute never
            contiguous,         // 1 bit  -  Contiguous
            dirty_bit_modifier, // 1 bit  -  DBM
            guarded_page,       // 1 bit  -  GP
            page_frame_number,  // 38 bits - Page frame number
            not_global,         // 1 bit  -  Not global
            access_flag,        // 1 bit  -  Access flag
            shareable,          // 2 bits -  SH 0 = Non-shareable, 2 = Outer Shareable, 3 = Inner Shareable
            access_permission,  // 2 bits -  Access permissions
            non_secure,         // 1 bit  -  Non-secure
            attribute_index,    // 3 bits -  Used for caching attributes
            table_desc,         // 1 bit  -  Table descriptor, 1 = Table descriptor for look up level 0, 1, 2
            valid,              // 1 bit  -  Valid descriptor
        );

        Ok(())
    }

    fn unmap(&mut self, va: VirtualAddress) {
        // PageTableEntryAArch64 is Copy, so we can make a copy to modify and then swap it in
        let mut entry = *self;
        entry.0 = 0;
        self.swap_entry(entry.0, va.into());
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use crate::arch::PageTableEntry;

    fn make_pa(addr: u64) -> PhysicalAddress {
        PhysicalAddress::from(addr)
    }

    #[test]
    fn test_descriptor_valid_table() {
        let mut desc = PageTableEntryAArch64::new();
        assert!(!desc.is_valid_table());

        desc.set_valid(true);
        desc.set_table_desc(true);
        assert!(desc.is_valid_table());
    }

    #[test]
    fn test_get_canonical_page_table_base() {
        let mut desc = PageTableEntryAArch64::new();
        let pa = 0x1234_5600_0000u64;
        desc.set_page_frame_number(pa >> 12);
        let base = desc.get_canonical_page_table_base();
        assert_eq!(u64::from(base), pa & !0xfffu64);
    }

    #[test]
    fn test_update_fields_page_aligned() {
        let mut desc = PageTableEntryAArch64::new();
        let pa = make_pa(0x2000_0000);
        let attrs = MemoryAttributes::Writeback;
        assert!(desc.update_fields(attrs, pa, true, PageLevel::Level1, pa.into()).is_ok());
        assert_eq!(desc.page_frame_number(), 0x2000_0000 >> 12);
        assert!(desc.valid());
    }

    #[test]
    fn test_update_fields_unaligned() {
        let mut desc = PageTableEntryAArch64::new();
        let pa = make_pa(0x2000_0001); // not aligned
        let attrs = MemoryAttributes::Writeback;
        let res = desc.update_fields(attrs, pa, true, PageLevel::Level1, pa.into());
        assert!(matches!(res, Err(PtError::UnalignedPageBase)));
    }

    #[test]
    fn test_set_attributes_invalid() {
        let mut desc = PageTableEntryAArch64::new();
        let attrs = MemoryAttributes::from_bits_truncate(0xFFFF_FFFF); // invalid bits
        let res = desc.set_attributes(attrs);
        assert!(res.is_err());
    }

    #[test]
    fn test_set_attributes_execute_protect() {
        let mut desc = PageTableEntryAArch64::new();
        let attrs = MemoryAttributes::Writeback | MemoryAttributes::ExecuteProtect;
        desc.set_attributes(attrs).unwrap();
        assert!(desc.uxn());
        assert!(!desc.pxn());
    }

    #[test]
    fn test_set_attributes_readonly() {
        let mut desc = PageTableEntryAArch64::new();
        let attrs = MemoryAttributes::Writeback | MemoryAttributes::ReadOnly;
        desc.set_attributes(attrs).unwrap();
        assert_eq!(desc.access_permission(), 2);
    }

    #[test]
    fn test_set_attributes_readprotect() {
        let mut desc = PageTableEntryAArch64::new();
        let attrs = MemoryAttributes::Writeback | MemoryAttributes::ReadProtect;
        desc.set_attributes(attrs).unwrap();
        assert!(!desc.valid());
    }

    #[test]
    fn test_get_attributes_uncacheable() {
        let mut desc = PageTableEntryAArch64::new();
        desc.set_valid(true);
        desc.set_attribute_index(0);
        let attrs = desc.get_attributes();
        assert!(attrs.contains(MemoryAttributes::Uncacheable));
    }

    #[test]
    fn test_get_attributes_writeback_readonly_execute() {
        let mut desc = PageTableEntryAArch64::new();
        desc.set_valid(true);
        desc.set_attribute_index(3);
        desc.set_access_permission(2);
        desc.set_uxn(true);
        let attrs = desc.get_attributes();
        assert!(attrs.contains(MemoryAttributes::Writeback));
        assert!(attrs.contains(MemoryAttributes::ReadOnly));
        assert!(attrs.contains(MemoryAttributes::ExecuteProtect));
    }

    #[test]
    fn test_get_attributes_readprotect() {
        let mut desc = PageTableEntryAArch64::new();
        desc.set_valid(false);
        let attrs = desc.get_attributes();
        assert!(attrs.contains(MemoryAttributes::ReadProtect));
    }

    #[test]
    fn test_dump_entry_runs() {
        let desc = PageTableEntryAArch64::new();
        let va = VirtualAddress::from(0x1000u64);
        let level = PageLevel::Level3;
        // Should not panic or error
        let _ = desc.dump_entry(va, level);
    }
}
