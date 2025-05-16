use crate::{
    structs::{PageLevel, PhysicalAddress, VirtualAddress},
    MemoryAttributes, PtError, PtResult,
};
use bitfield_struct::bitfield;

// This is the maximum virtual address that can be used in the system because of our artifical restriction to use
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
pub(crate) const FOUR_LEVEL_4_SELF_MAP_BASE: u64 = 0xFFFF_FFFF_F000;
pub(crate) const FOUR_LEVEL_3_SELF_MAP_BASE: u64 = 0xFFFF_FFE0_0000;
pub(crate) const FOUR_LEVEL_2_SELF_MAP_BASE: u64 = 0xFFFF_C000_0000;
pub(crate) const FOUR_LEVEL_1_SELF_MAP_BASE: u64 = 0xFF80_0000_0000;

// Below is a common definition for the AArch64 VMSAv8-64 stage-1 decriptors. This uses
// the common understanding of bits accross all levels/types to simplify translation
// as well as to allow for recursive translation.
#[rustfmt::skip]
#[bitfield(u64)]
pub struct AArch64Descriptor {
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

impl AArch64Descriptor {
    pub fn is_valid_table(&self) -> bool {
        self.valid() && self.table_desc()
    }

    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        // This logic will need to be specialized if 16Kb or 64Kb granules are used.
        (self.page_frame_number() << PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT).into()
    }

    /// update all the fields and table base address
    pub fn update_fields(&mut self, attributes: MemoryAttributes, next_pa: PhysicalAddress) -> PtResult<()> {
        if !next_pa.is_page_aligned() {
            return Err(PtError::UnalignedPageBase);
        }

        let next_level_table_base: u64 = next_pa.into();
        let pfn = next_level_table_base >> PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT;
        self.set_page_frame_number(pfn);

        self.set_valid(true);

        // update the memory attributes irrespective of new or old page table
        self.set_attributes(attributes);

        // TODO: need to flush the cache if operating on the active page table
        Ok(())
    }

    fn set_attributes(&mut self, attributes: MemoryAttributes) {
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
                panic!("Invalid memory attributes: {:?}", attributes);
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
    }

    /// return all the memory attributes for the current entry
    pub fn get_attributes(&self) -> MemoryAttributes {
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

    pub fn dump_entry(&self, va: VirtualAddress, level: PageLevel) {
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
            va + level.entry_va_size() - 1,
            "",
            ns_table,            // 1 bit  -  Secure state, only for accessing in Secure IPA or PA space.
            ap_table,            // 2 bits -  Hierarchical permissions.
            uxn_table,           // 1 bit  -  Hierarchical permissions.
            pxn_table,           // 1 bit  -  Hierarchical permissions.
            reserved0,           // 4 bits -  Reserved for software use
            uxn,                 // 1 bit  -  User execute never
            pxn,                 // 1 bit  -  Privileged execute never
            contiguous,          // 1 bit  -  Contiguous
            dirty_bit_modifier,  // 1 bit  -  DBM
            guarded_page,        // 1 bit  -  GP
            page_frame_number,   // 38 bits - Page frame number
            not_global,          // 1 bit  -  Not global
            access_flag,         // 1 bit  -  Access flag
            shareable,           // 2 bits -  SH 0 = Non-shareable, 2 = Outer Shareable, 3 = Inner Shareable
            access_permission,   // 2 bits -  Access permissions
            non_secure,          // 1 bit  -  Non-secure
            attribute_index,    // 3 bits -  Used for caching attributes
            table_desc,          // 1 bit  -  Table descriptor, 1 = Table descriptor for look up level 0, 1, 2
            valid,               // 1 bit  -  Valid descriptor
        )
    }

    pub fn get_u64(&self) -> u64 {
        self.0
    }
}
