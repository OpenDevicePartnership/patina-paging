use bitfield_struct::bitfield;
use core::{
    fmt::{self, Display, Formatter},
    ops::{Add, Sub},
};

use crate::{MemoryAttributes, PtError, PtResult};

pub(crate) const MAX_VA: u64 = 0x0000_ffff_ffff_ffff;

const LEVEL0_START_BIT: u64 = 39;
const LEVEL1_START_BIT: u64 = 30;
const LEVEL2_START_BIT: u64 = 21;
const LEVEL3_START_BIT: u64 = 12;

/// TODO: This needs to be moved some common places
pub(crate) const FRAME_SIZE_4KB: u64 = 0x1000; // 4KB
pub(crate) const PAGE_SIZE: u64 = 0x1000; // 4KB
pub(crate) const INDEX_MASK: u64 = 0x1FF;

const PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_LOWER_SHIFT: u64 = 12u64; // lower 12 bits for alignment
const PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_LOWER_MASK: u64 = 0x000f_ffff_ffff_f000u64; // 40 bit - lower 12 bits for alignment

const PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_UPPER_SHIFT: u64 = 2u64; // bit 51:50
const PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_UPPER_MASK: u64 = 0x0030_0000_0000_0000u64; // 2 bits - bit 51:50

fn is_4kb_aligned(addr: u64) -> bool {
    (addr & (FRAME_SIZE_4KB - 1)) == 0
}

// Below is the implementation of the block descriptor for AArch64 systems.
// The bitfields are defined following the VMSAv8-64, stage 1 translation
// descriptor format.
#[rustfmt::skip]
#[bitfield(u64)]
pub struct VMSAv864TableDescriptor {
    pub valid_desc: bool,          // 1 bit -  Valid descriptor
    pub table_desc: bool,          // 1 bit -  Table descriptor, 1 = Table descriptor for look up level 0, 1, 2
    #[bits(6)]
    pub ignored0: u8,              // 6 bits -  Not used.
    #[bits(2)]
    pub nlta_upper: u8,            // 2 bits -  NTLA for 4KB or 16KB granule
    pub access_flag: bool,         // 1 bit  -  When hardware managed access flag is enabled
    pub ignored1: bool,            // 1 bit  -  Not used.
    #[bits(40)]
    pub nlta_lower: u64,           // 40 bits - Address to the next level table descriptor, depending on the granule.
    pub ignored2: bool,            // 1 bit  -  Not used with PnCH being 0.
    #[bits(6)]
    pub ignored3: u8,              // 6 bits -  Not used.
    pub pxn_table: bool,           // 1 bit  -  Hierarchical permissions.
    pub uxn_table: bool,           // 1 bit  -  Hierarchical permissions.
    #[bits(2)]
    pub ap_table: u8,              // 2 bits -  Hierarchical permissions.
    pub ns_table: bool,            // 1 bit  -  Secure state, only for accessing in Secure IPA or PA space.
}

impl VMSAv864TableDescriptor {
    pub fn is_valid_table(&self) -> bool {
        self.valid_desc() && self.table_desc()
    }

    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        let nlta_lower = self.nlta_lower() << PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_LOWER_SHIFT;
        let nlta_upper = (self.nlta_upper() as u64) << PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_UPPER_SHIFT;
        PhysicalAddress(nlta_lower | nlta_upper)
    }

    /// update all the fields and table base address
    pub fn update_fields(&mut self, attributes: u64, next_pa: PhysicalAddress) -> PtResult<()> {
        if !self.is_valid_table() {
            let next_level_table_base = next_pa.into();
            if !is_4kb_aligned(next_level_table_base) {
                panic!("allocated page is not 4k aligned {:X}", next_level_table_base);
            }

            // println!("next_level_table_base: {:X}", next_level_table_base);
            let nlta_lower = (next_level_table_base & PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_LOWER_MASK)
                >> PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_LOWER_SHIFT;
            let nlta_upper = ((next_level_table_base & PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_UPPER_MASK)
                >> PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_UPPER_SHIFT) as u8;

            self.set_nlta_lower(nlta_lower);
            self.set_nlta_upper(nlta_upper);
            self.set_table_desc(true);
            self.set_valid_desc(true);
        }

        // update the memory attributes irrespective of new or old page table
        self.set_attributes(attributes);

        // TODO: need to flush the cache if operating on the active page table
        Ok(())
    }

    /// return all the memory attributes for the current entry
    fn set_attributes(&mut self, _attributes: u64) {
        // For table entries, we don't need to set the memory attributes
        // Instead, we need to set the most permissive attributes to allow page
        // entries to drive the attributes.
        self.set_ap_table(0);
        self.set_pxn_table(false);
        self.set_uxn_table(false);
    }

    /// return all the memory attributes for the current entry
    pub fn get_attributes(&mut self) -> u64 {
        let mut attributes = MemoryAttributes::empty();

        if !self.is_valid_table() {
            attributes |= MemoryAttributes::ReadProtect;
        }

        if (self.ap_table() == 0b10) | (self.ap_table() == 0b11) {
            attributes |= MemoryAttributes::ReadOnly;
        }

        if self.uxn_table() | self.pxn_table() {
            // TODO: need to check if the system in EL2 or EL1
            attributes |= MemoryAttributes::ExecuteProtect;
        }

        attributes.bits()
    }

    pub fn set_table_invalid(&mut self) {
        self.set_valid_desc(false);
    }
}

// Below is the implementation of the block descriptor for AArch64 systems.
// The bitfields are defined following the VMSAv8-64, stage 1 translation
// descriptor format.
#[rustfmt::skip]
#[bitfield(u64)]
pub struct VMSAv864PageDescriptor {
    #[bits(2)]
    pub descriptor_type: u8,      // 2 bits -  1 = Block entry, 3 = Page entry or level 3 block entry, Others = Faulty entry
    #[bits(3)]
    pub attribute_index: u8,      // 3 bits -  AttrIndx 0 = Device memory, 1 = non-cacheable memory, 2 = write-through, 3 = write-back, 4 = write-back.
    pub ns: bool,                 // 1 bit  -  NS
    #[bits(2)]
    pub access_permission: u8,    // 2 bits -  AP
    #[bits(2)]
    pub shareable: u8,            // 2 bits -  SH 0 = Non-shareable, 2 = Outer Shareable, 3 = Inner Shareable
    pub access_flag: bool,        // 1 bit  -  Access flag
    pub ng: bool,                 // 1 bit  -  Not global
    #[bits(9)]
    pub level3_index: u16,        // 9 bits -  Level 3 index, that points to a 4KB block
    #[bits(9)]
    pub level2_index: u16,        // 9 bits -  Level 2 index, that points to L3 table or a 2MB block
    #[bits(9)]
    pub level1_index: u16,        // 9 bits -  Level 1 index, that points to L2 table or a 1GB block
    #[bits(9)]
    pub level0_index: u16,        // 9 bits -  Level 0 index, that points to L1 table or a 512GB block
    #[bits(2)]
    pub reserved0: u8,            // 2 bits -  Not used
    pub guarded_page: bool,       // 1 bit  -  GP
    pub dirty_bit_modifier: bool, // 1 bit  -  DBM
    pub contig: bool,             // 1 bit  -  Contiguous
    pub pxn: bool,                // 1 bit  -  PXN Execution permissions
    pub uxn: bool,                // 1 bit  -  UXN Execution permissions
    #[bits(4)]
    pub reserved1: u8,            // 3 bits -  Reserved for software use
    #[bits(4)]
    pub imp_def: u8,              // 4 bits -  Implementation defined
    pub ignored: bool,            // 1 bit  -  Not used outside of Realm translation regimes
}

impl VMSAv864PageDescriptor {
    pub fn is_valid_page(&self) -> bool {
        self.descriptor_type() == 3
    }

    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        let level3_index = (self.level3_index() as u64) << LEVEL3_START_BIT;
        let level2_index = (self.level2_index() as u64) << LEVEL2_START_BIT;
        let level1_index = (self.level1_index() as u64) << LEVEL1_START_BIT;
        let level0_index = (self.level0_index() as u64) << LEVEL0_START_BIT;

        PhysicalAddress(level3_index | level2_index | level1_index | level0_index)
    }

    fn set_attributes(&mut self, attributes: u64) {
        let attributes = MemoryAttributes::from_bits_truncate(attributes);
        // This change pretty much follows the GcdAttributeToPageAttribute
        match attributes & MemoryAttributes::CacheAttributeMask {
            MemoryAttributes::Uncacheable => {
                self.set_attribute_index(0);
                self.set_ng(false);
                self.set_ns(false);
            }
            MemoryAttributes::WriteCombining => {
                self.set_attribute_index(1);
                self.set_ng(false);
                self.set_ns(false);
            }
            MemoryAttributes::WriteThrough => {
                self.set_attribute_index(2);
                self.set_ng(false);
                self.set_ns(false);
            }
            MemoryAttributes::Writeback => {
                self.set_attribute_index(3);
                self.set_ng(false);
                self.set_ns(false);
            }
            MemoryAttributes::UncacheableExport => {
                self.set_attribute_index(4);
                self.set_ng(false);
                self.set_ns(false);
            }
            _ => {
                self.set_attribute_index(0);
                self.set_ng(true);
                self.set_ns(false);
            }
        }

        if attributes.contains(MemoryAttributes::ExecuteProtect)
            || (attributes & MemoryAttributes::CacheAttributeMask == MemoryAttributes::Uncacheable)
        {
            // TODO: need to check if the system in EL2 or EL1
            self.set_uxn(true);
            self.set_pxn(false);
        }

        if attributes.contains(MemoryAttributes::ReadOnly) {
            self.set_access_permission(2);
        }
        self.set_access_flag(true);
    }

    /// return all the memory attributes for the current entry
    pub fn get_attributes(&self) -> u64 {
        let mut attributes = MemoryAttributes::empty();

        if !self.is_valid_page() {
            attributes = MemoryAttributes::ReadProtect;
        } else {
            match self.attribute_index() {
                0 => attributes |= MemoryAttributes::Uncacheable,
                1 => attributes |= MemoryAttributes::WriteCombining,
                2 => attributes |= MemoryAttributes::WriteThrough,
                3 => attributes |= MemoryAttributes::Writeback,
                4 => attributes |= MemoryAttributes::UncacheableExport,
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
        attributes.bits()
    }

    /// update all the fields and table base address
    pub fn update_fields(&mut self, attributes: u64, page_table_base_address: PhysicalAddress) -> PtResult<()> {
        if !self.is_valid_page() {
            let next_level_table_base = u64::from(page_table_base_address);

            let lvl3_index: u16 = ((next_level_table_base >> LEVEL3_START_BIT) & INDEX_MASK) as u16;
            self.set_level3_index(lvl3_index);
            let lvl2_index: u16 = ((next_level_table_base >> LEVEL2_START_BIT) & INDEX_MASK) as u16;
            self.set_level2_index(lvl2_index);
            let lvl1_index: u16 = ((next_level_table_base >> LEVEL1_START_BIT) & INDEX_MASK) as u16;
            self.set_level1_index(lvl1_index);
            let lvl0_index: u16 = ((next_level_table_base >> LEVEL0_START_BIT) & INDEX_MASK) as u16;
            self.set_level0_index(lvl0_index);

            self.set_descriptor_type(3);
        }

        // update the memory attributes irrespective of new or old page table
        self.set_attributes(attributes);

        // TODO: need to flush the cache if operating on the active page table
        Ok(())
    }

    pub fn set_page_invalid(&mut self) {
        self.set_descriptor_type(0);
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum PageLevel {
    Lvl0 = 4,
    Lvl1 = 3,
    Lvl2 = 2,
    Lvl3 = 1,
    NA = 0,
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
            0 => PageLevel::NA,
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

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct VirtualAddress(u64);
impl VirtualAddress {
    pub fn new(va: u64) -> Self {
        Self(va)
    }

    pub fn round_up(&self, level: PageLevel) -> VirtualAddress {
        let va = self.0;
        match level {
            // TODO: fix these to use intrinsics
            PageLevel::Lvl0 => Self((((va >> LEVEL0_START_BIT) + 1) << LEVEL0_START_BIT) - 1),
            PageLevel::Lvl1 => Self((((va >> LEVEL1_START_BIT) + 1) << LEVEL1_START_BIT) - 1),
            PageLevel::Lvl2 => Self((((va >> LEVEL2_START_BIT) + 1) << LEVEL2_START_BIT) - 1),
            PageLevel::Lvl3 => Self((((va >> LEVEL3_START_BIT) + 1) << LEVEL3_START_BIT) - 1),
            _ => panic!("Invalid level: {:?}", level),
        }
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
            _ => panic!("Invalid level: {:?}", level),
        }
    }

    pub fn is_4kb_aligned(&self) -> bool {
        let va: u64 = self.0;
        (va & (FRAME_SIZE_4KB - 1)) == 0
    }

    pub fn is_2mb_aligned(&self) -> bool {
        let va: u64 = self.0;
        (va & (FRAME_SIZE_2MB - 1)) == 0
    }

    pub fn min(lhs: VirtualAddress, rhs: VirtualAddress) -> VirtualAddress {
        VirtualAddress(core::cmp::min(lhs.0, rhs.0))
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

const FRAME_SIZE_2MB: u64 = 0x200000; // 2MB

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct PhysicalAddress(u64);
impl PhysicalAddress {
    pub fn new(va: u64) -> Self {
        Self(va)
    }

    pub fn is_4kb_aligned(&self) -> bool {
        let va: u64 = self.0;
        (va & (FRAME_SIZE_4KB - 1)) == 0
    }

    pub fn is_2mb_aligned(&self) -> bool {
        let va: u64 = self.0;
        (va & (FRAME_SIZE_2MB - 1)) == 0
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
