use core::{
    fmt::{self, Display, Formatter},
    ops::{Add, Sub},
};

use bitfield_struct::bitfield;

use crate::{
    page_table_error::PtResult,
    {EFI_MEMORY_RO, EFI_MEMORY_RP, EFI_MEMORY_XP},
};

pub const PAGE_SIZE: u64 = 0x1000; // 4KB
const PAGE_INDEX_MASK: u64 = 0x1FF;

pub(crate) const MAX_PML5_VA: u64 = 0x01ff_ffff_ffff_ffff;
pub(crate) const MAX_PML4_VA: u64 = 0x0000_ffff_ffff_ffff;

const PML5_START_BIT: u64 = 48;
const PML4_START_BIT: u64 = 39;
const PDP_START_BIT: u64 = 30;
const PD_START_BIT: u64 = 21;
const PT_START_BIT: u64 = 12;

pub(crate) const CR3_PAGE_BASE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000; // 40 bit - lower 12 bits for alignment

const PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT: u64 = 12u64; // lower 12 bits for alignment
const PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000; // 40 bit - lower 12 bits for alignment

#[rustfmt::skip]
#[bitfield(u64)]
pub struct PageMapEntry {
    pub present: bool,                // 1 bit -  0 = Not present in memory, 1 = Present in memory
    pub read_write: bool,             // 1 bit -  0 = Read-Only, 1= Read/Write
    pub user_supervisor: bool,        // 1 bit -  0 = Supervisor, 1=User
    pub write_through: bool,          // 1 bit -  0 = Write-Back caching, 1=Write-Through caching
    pub cache_disabled: bool,         // 1 bit -  0 = Cached, 1=Non-Cached
    pub accessed: bool,               // 1 bit -  0 = Not accessed, 1 = Accessed (set by CPU)
    pub reserved: bool,               // 1 bit -  Reserved
    #[bits(2)]
    pub must_be_zero: u8,             // 2 bits -  Must Be Zero
    #[bits(3)]
    pub available: u8,                // 3 bits -  Available for use by system software
    #[bits(40)]
    pub page_table_base_address: u64, // 40 bits -  Page Table Base Address
    #[bits(11)]
    pub available_high: u16,          // 11 bits -  Available for use by system software
    pub nx: bool,                     // 1 bit -  No Execute bit
}

impl PageMapEntry {
    /// update all the fields and table base address
    pub fn update_fields(&mut self, attributes: u64, pa: PhysicalAddress) -> PtResult<()> {
        if !self.present() {
            let mut next_level_table_base: u64 = pa.into();

            next_level_table_base &= PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_MASK;
            next_level_table_base >>= PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT;

            self.set_page_table_base_address(next_level_table_base);
            self.set_present(true);
        }

        // update the memory attributes irrespective of new or old page table
        self.set_attributes(attributes);
        Ok(())
    }

    /// return the 40 bits table base address converted to canonical address
    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        let mut page_table_base_address = self.page_table_base_address();

        page_table_base_address <<= PAGE_MAP_ENTRY_PAGE_TABLE_BASE_ADDRESS_SHIFT;

        PhysicalAddress(page_table_base_address)
    }

    /// return all the memory attributes for the current entry
    pub fn get_attributes(&self) -> u64 {
        let mut attributes = 0u64;

        if !self.present() {
            attributes |= EFI_MEMORY_RP;
        }

        if !self.read_write() {
            attributes |= EFI_MEMORY_RO;
        }

        if self.nx() {
            attributes |= EFI_MEMORY_XP;
        }

        attributes
    }

    /// set all the memory attributes for the current entry
    fn set_attributes(&mut self, _attributes: u64) {
        self.set_read_write(true);
        self.set_user_supervisor(true);
        self.set_write_through(false);
        self.set_cache_disabled(false);
        self.set_must_be_zero(0);
        self.set_available(0);
        self.set_available_high(0);
        self.set_nx(false);
    }
}

pub(crate) const FRAME_SIZE_4KB: u64 = 0x1000; // 4KB
pub(crate) const PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT: u64 = 12u64; // lower 12 bits for alignment
pub(crate) const PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000; // 40 bit - lower 12 bits for alignment

#[rustfmt::skip]
#[bitfield(u64)]
pub struct PageTableEntry4KB {
    pub present: bool,                // 1 bit -  0 = Not present in memory, 1 = Present in memory
    pub read_write: bool,             // 1 bit -  0 = Read-Only, 1= Read/Write
    pub user_supervisor: bool,        // 1 bit -  0 = Supervisor, 1=User
    pub write_through: bool,          // 1 bit -  0 = Write-Back caching, 1=Write-Through caching
    pub cache_disabled: bool,         // 1 bit -  0 = Cached, 1=Non-Cached
    pub accessed: bool,               // 1 bit -  0 = Not accessed, 1 = Accessed (set by CPU)
    pub dirty: bool,                  // 1 bit -  0 = Not Dirty, 1 = written by processor on access to page
    pub pat: bool,                    // 1 bit
    pub global: bool,                 // 1 bit -  0 = Not global page, 1 = global page TLB not cleared on CR3 write
    #[bits(3)]
    pub available: u8,                // 3 bits -  Available for use by system software
    #[bits(40)]
    pub page_table_base_address: u64, // 40 bits -  Page Table Base Address
    #[bits(11)]
    pub available_high: u16,          // 11 bits -  Available for use by system software
    pub nx: bool,                     // 1 bit -  0 = Execute Code, 1 = No Code Execution
}

impl PageTableEntry4KB {
    /// update all the fields and next table base address
    pub fn update_fields(&mut self, attributes: u64, pa: PhysicalAddress) -> PtResult<()> {
        if !self.present() {
            let mut next_level_table_base: u64 = pa.into();

            next_level_table_base &= PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_MASK;
            next_level_table_base >>= PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT;

            self.set_page_table_base_address(next_level_table_base);
            self.set_present(true);
        }

        // update the memory attributes irrespective of new or old page table
        self.set_attributes(attributes);
        Ok(())
    }

    /// return all the memory attributes for the current entry
    pub fn get_attributes(&self) -> u64 {
        let mut attributes = 0u64;

        if !self.present() {
            attributes |= EFI_MEMORY_RP;
        }

        if !self.read_write() {
            attributes |= EFI_MEMORY_RO;
        }

        if self.nx() {
            attributes |= EFI_MEMORY_XP;
        }

        attributes
    }

    /// set all the memory attributes for the current entry
    fn set_attributes(&mut self, attributes: u64) {
        if (attributes & EFI_MEMORY_RP) != 0 {
            self.set_present(false);
        } else {
            self.set_present(true);
        }

        if (attributes & EFI_MEMORY_RO) != 0 {
            self.set_read_write(false);
        } else {
            self.set_read_write(true);
        }

        self.set_user_supervisor(true);
        self.set_write_through(false);
        self.set_cache_disabled(false);
        self.set_pat(false);
        self.set_global(false);
        self.set_available(0);
        self.set_available_high(0);

        if (attributes & EFI_MEMORY_XP) != 0 {
            self.set_nx(true);
        } else {
            self.set_nx(false);
        }
    }

    /// return the 40 bits table base address converted to canonical address
    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        let mut page_table_base_address = self.page_table_base_address();

        page_table_base_address <<= PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT;

        PhysicalAddress(page_table_base_address)
    }
}

#[derive(PartialEq, Clone, Copy)]
pub enum PageLevel {
    Pml5 = 5,
    Pml4 = 4,
    Pdp = 3,
    Pd = 2,
    Pt = 1,
    Pa = 0,
}

impl From<PageLevel> for u64 {
    fn from(value: PageLevel) -> u64 {
        value as u64
    }
}

impl From<u64> for PageLevel {
    fn from(value: u64) -> PageLevel {
        match value {
            5 => PageLevel::Pml5,
            4 => PageLevel::Pml4,
            3 => PageLevel::Pdp,
            2 => PageLevel::Pd,
            1 => PageLevel::Pt,
            0 => PageLevel::Pa,
            _ => panic!("Invalid value for PageLevel: {}", value),
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

    /// This will return the max va addressable by the current entry
    /// For example:
    ///                          |      PML5|     PML4| PDP/PML3|  PD/PML2|  PT/PML1|    Physical
    /// va               = 000000|0000000000|000000000|000000000|000000011|000000000|000000000000
    /// round_up(va, PD) = 000000|0000000000|000000000|000000000|000000011|111111111|111111111111
    pub fn round_up(&self, level: PageLevel) -> VirtualAddress {
        let va = self.0;
        match level {
            // TODO: fix these to use intrinsics
            PageLevel::Pml5 => Self((((va >> PML5_START_BIT) + 1) << PML5_START_BIT) - 1),
            PageLevel::Pml4 => Self((((va >> PML4_START_BIT) + 1) << PML4_START_BIT) - 1),
            PageLevel::Pdp => Self((((va >> PDP_START_BIT) + 1) << PDP_START_BIT) - 1),
            PageLevel::Pd => Self((((va >> PD_START_BIT) + 1) << PD_START_BIT) - 1),
            PageLevel::Pt => Self((((va >> PT_START_BIT) + 1) << PT_START_BIT) - 1),
            PageLevel::Pa => Self(va),
        }
    }

    /// This will return the next va addressable by the current entry
    /// For example:
    ///                             |      PML5|     PML4| PDP/PML3|  PD/PML2|  PT/PML1|    Physical
    /// va                  = 000000|0000000000|000000000|000000000|000000011|000000000|000000000000
    /// get_next_va(va, PD) = 000000|0000000000|000000000|000000000|000000100|000000000|000000000000
    ///
    pub fn get_next_va(&self, level: PageLevel) -> VirtualAddress {
        self.round_up(level) + 1
    }

    pub fn get_index(&self, level: PageLevel) -> u64 {
        let va = self.0;
        match level {
            // TODO: fix these to use intrinsics
            PageLevel::Pml5 => (va >> PML5_START_BIT) & PAGE_INDEX_MASK,
            PageLevel::Pml4 => (va >> PML4_START_BIT) & PAGE_INDEX_MASK,
            PageLevel::Pdp => (va >> PDP_START_BIT) & PAGE_INDEX_MASK,
            PageLevel::Pd => (va >> PD_START_BIT) & PAGE_INDEX_MASK,
            PageLevel::Pt => (va >> PT_START_BIT) & PAGE_INDEX_MASK,
            PageLevel::Pa => panic!("get_index is not expected to be called"),
        }
    }

    pub fn is_4kb_aligned(&self) -> bool {
        let va: u64 = self.0;
        (va & (FRAME_SIZE_4KB - 1)) == 0
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

impl Sub<u64> for VirtualAddress {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        match self.0.checked_sub(rhs) {
            Some(result) => VirtualAddress(result),
            None => panic!("Underflow occurred!"),
        }
    }
}

impl From<PhysicalAddress> for VirtualAddress {
    fn from(va: PhysicalAddress) -> Self {
        Self(va.0)
    }
}

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
