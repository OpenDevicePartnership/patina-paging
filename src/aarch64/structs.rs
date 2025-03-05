use crate::{MemoryAttributes, PtError, PtResult};
use alloc::string::String;
use bitfield_struct::bitfield;
use core::{
    fmt::{self, Display, Formatter},
    ops::{Add, Sub},
};

pub(crate) const MAX_VA: u64 = 0x0000_ffff_ffff_ffff;

// this is the maximum physical address that can be used in the system because of our artifical restriction to use
// the zero VA and self map index in the top level page table. This is a temporary restriction
pub(crate) const MAX_PA: u64 = 0x0000_feff_ffff_ffff;

const LEVEL0_START_BIT: u64 = 39;
const LEVEL1_START_BIT: u64 = 30;
const LEVEL2_START_BIT: u64 = 21;
const LEVEL3_START_BIT: u64 = 12;

/// TODO: This needs to be moved some common places
pub(crate) const FRAME_SIZE_4KB: u64 = 0x1000; // 4KB
pub(crate) const PAGE_SIZE: u64 = 0x1000; // 4KB
pub(crate) const INDEX_MASK: u64 = 0x1FF;

const PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT: u64 = 12u64; // lower 12 bits for alignment

fn is_4kb_aligned(addr: u64) -> bool {
    (addr & (FRAME_SIZE_4KB - 1)) == 0
}

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
        if !self.is_valid_table() {
            let next_level_table_base = next_pa.into();
            if !is_4kb_aligned(next_level_table_base) {
                panic!("allocated page is not 4k aligned {:X}", next_level_table_base);
            }

            let pfn = next_level_table_base >> PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT;
            self.set_page_frame_number(pfn);

            // TODO this needs to change for large pages.
            self.set_table_desc(true);
            self.set_valid(true);
        }

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
            // TODO: this needs to be updated for large pages.
            self.set_table_desc(true);
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

    pub fn dump_entry(&self) -> String {
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

        format!(
            "|{:01b}|{:02b}|{:01b}|{:01b}|{:04b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:038b}|{:01b}|{:01b}|{:02b}|{:02b}|{:01b}|{:03b}|{:01b}|{:01b}|",
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

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum PageLevel {
    Lvl0 = 4,
    Lvl1 = 3,
    Lvl2 = 2,
    Lvl3 = 1,
}

impl PageLevel {
    pub fn start_bit(&self) -> u64 {
        match self {
            PageLevel::Lvl0 => LEVEL0_START_BIT,
            PageLevel::Lvl1 => LEVEL1_START_BIT,
            PageLevel::Lvl2 => LEVEL2_START_BIT,
            PageLevel::Lvl3 => LEVEL3_START_BIT,
        }
    }

    pub fn entry_va_size(&self) -> u64 {
        1 << self.start_bit()
    }

    pub fn supports_block_entry(&self) -> bool {
        match self {
            PageLevel::Lvl3 => true,
            // Large pages could be disabled by a crate feature in the future.
            PageLevel::Lvl1 | PageLevel::Lvl2 => true,
            _ => false,
        }
    }
}

impl From<PageLevel> for u64 {
    fn from(value: PageLevel) -> u64 {
        value as u64
    }
}

impl From<u64> for PageLevel {
    fn from(value: u64) -> PageLevel {
        match value {
            4 => PageLevel::Lvl0,
            3 => PageLevel::Lvl1,
            2 => PageLevel::Lvl2,
            1 => PageLevel::Lvl3,
            _ => panic!("Invalid page level: {}", value),
        }
    }
}

impl Sub<u64> for PageLevel {
    type Output = Self;

    fn sub(self, _rhs: u64) -> Self::Output {
        ((self as u64) - 1).into()
    }
}

impl fmt::Display for PageLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level_name = match self {
            PageLevel::Lvl0 => "LVL0",
            PageLevel::Lvl1 => "LVL1",
            PageLevel::Lvl2 => "LVL2",
            PageLevel::Lvl3 => "LVL3",
        };
        write!(f, "{:5}", level_name)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct VirtualAddress(u64);
impl VirtualAddress {
    pub fn new(va: u64) -> Self {
        Self(va)
    }

    pub fn round_up(&self, level: PageLevel) -> VirtualAddress {
        let va = self.0;
        let start_bit = level.start_bit();
        Self((((va >> start_bit) + 1) << start_bit) - 1)
    }

    pub fn get_next_va(&self, level: PageLevel) -> VirtualAddress {
        self.round_up(level) + 1
    }

    pub fn get_index(&self, level: PageLevel) -> u64 {
        let va = self.0;
        match level {
            // TODO: fix these to use intrinsics
            PageLevel::Lvl0 => (va >> LEVEL0_START_BIT) & INDEX_MASK,
            PageLevel::Lvl1 => (va >> LEVEL1_START_BIT) & INDEX_MASK,
            PageLevel::Lvl2 => (va >> LEVEL2_START_BIT) & INDEX_MASK,
            PageLevel::Lvl3 => (va >> LEVEL3_START_BIT) & INDEX_MASK,
        }
    }

    pub fn is_level_aligned(&self, level: PageLevel) -> bool {
        let va = self.0;
        va & (level.entry_va_size() - 1) == 0
    }

    pub fn is_4kb_aligned(&self) -> bool {
        let va: u64 = self.0;
        (va & (FRAME_SIZE_4KB - 1)) == 0
    }

    pub fn min(lhs: VirtualAddress, rhs: VirtualAddress) -> VirtualAddress {
        VirtualAddress(core::cmp::min(lhs.0, rhs.0))
    }

    /// This will return the range length between self and end (inclusive)
    pub fn length_through(&self, end: VirtualAddress) -> u64 {
        match end.0.checked_sub(self.0) {
            None => panic!("Underflow occurred! {:x} {:x}", self.0, end.0),
            Some(result) => result + 1,
        }
    }
}

impl From<u64> for VirtualAddress {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<VirtualAddress> for u64 {
    fn from(addr: VirtualAddress) -> Self {
        addr.0
    }
}

impl From<PhysicalAddress> for VirtualAddress {
    fn from(va: PhysicalAddress) -> Self {
        Self(va.0)
    }
}

impl Display for VirtualAddress {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(fmt, "0x{:016X}", self.0)
    }
}

impl Add<u64> for VirtualAddress {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        match self.0.checked_add(rhs) {
            Some(result) => VirtualAddress(result),
            None => panic!("Overflow occurred!"),
        }
    }
}

impl VirtualAddress {
    pub fn try_add(self, rhs: u64) -> PtResult<Self> {
        self.0.checked_add(rhs).map(VirtualAddress).ok_or(PtError::InvalidMemoryRange)
    }
}

impl Sub<u64> for VirtualAddress {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        match self.0.checked_sub(rhs) {
            Some(result) => VirtualAddress(result),
            None => panic!("Underflow occurred!"),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct PhysicalAddress(u64);
impl PhysicalAddress {
    pub fn new(va: u64) -> Self {
        Self(va)
    }

    pub fn is_4kb_aligned(&self) -> bool {
        let va: u64 = self.0;
        (va & (FRAME_SIZE_4KB - 1)) == 0
    }
}

impl From<u64> for PhysicalAddress {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<PhysicalAddress> for u64 {
    fn from(addr: PhysicalAddress) -> Self {
        addr.0
    }
}

impl Display for PhysicalAddress {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(fmt, "0x{:016X}", self.0)
    }
}

impl From<VirtualAddress> for PhysicalAddress {
    fn from(va: VirtualAddress) -> Self {
        Self(va.0)
    }
}
