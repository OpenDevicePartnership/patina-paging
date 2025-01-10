use crate::{MemoryAttributes, PtError, PtResult};
use alloc::string::String;
use bitfield_struct::bitfield;
use core::{
    fmt::{self, Display, Formatter},
    ops::{Add, Sub},
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

pub(crate) const FRAME_SIZE_4KB: u64 = 0x1000; // 4KB
pub(crate) const PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT: u64 = 12u64; // lower 12 bits for alignment
pub(crate) const PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000; // 40 bit - lower 12 bits for alignment

#[rustfmt::skip]
#[bitfield(u64)]
pub struct PageTableEntry {
    pub present: bool,                // 1 bit -  0 = Not present in memory, 1 = Present in memory
    pub read_write: bool,             // 1 bit -  0 = Read-Only, 1= Read/Write
    pub user_supervisor: bool,        // 1 bit -  0 = Supervisor, 1=User
    pub write_through: bool,          // 1 bit -  0 = Write-Back caching, 1=Write-Through caching
    pub cache_disabled: bool,         // 1 bit -  0 = Cached, 1=Non-Cached
    pub accessed: bool,               // 1 bit -  0 = Not accessed, 1 = Accessed (set by CPU)
    pub dirty: bool,                  // 1 bit -  0 = Not Dirty, 1 = written by processor on access to page
    pub page_size: bool,              // 1 bit
    pub global: bool,                 // 1 bit -  0 = Not global page, 1 = global page TLB not cleared on CR3 write
    #[bits(3)]
    pub available: u8,                // 3 bits -  Available for use by system software
    #[bits(40)]
    pub page_table_base_address: u64, // 40 bits -  Page Table Base Address
    #[bits(11)]
    pub available_high: u16,          // 11 bits -  Available for use by system software
    pub nx: bool,                     // 1 bit -  0 = Execute Code, 1 = No Code Execution
}

impl PageTableEntry {
    /// update all the fields and next table base address
    pub fn update_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress) -> PtResult<()> {
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
    pub fn get_attributes(&self) -> MemoryAttributes {
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

        PhysicalAddress(page_table_base_address)
    }

    pub fn dump_entry(&self) -> String {
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

        format!(
            "|{:01b}|{:011b}|{:040b}|{:03b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|{:01b}|",
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
            present                  // 1 bit -  0 = Not present in memory, 1 = Present in memory
        )
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum PageLevel {
    Pml5 = 5,
    Pml4 = 4,
    Pdp = 3,
    Pd = 2,
    Pt = 1,
    Pa = 0,
}

impl PageLevel {
    pub fn start_bit(&self) -> u64 {
        // TODO: fix these to use intrinsics
        match self {
            PageLevel::Pml5 => PML5_START_BIT,
            PageLevel::Pml4 => PML4_START_BIT,
            PageLevel::Pdp => PDP_START_BIT,
            PageLevel::Pd => PD_START_BIT,
            PageLevel::Pt => PT_START_BIT,
            PageLevel::Pa => panic!("Start bit is not defined for PA!"),
        }
    }

    pub fn entry_va_size(&self) -> u64 {
        1 << self.start_bit()
    }

    pub fn supports_pa_entry(&self) -> bool {
        match self {
            PageLevel::Pt => true,
            // TODO: Allow crate level disablement.
            PageLevel::Pd | PageLevel::Pdp => true,
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

impl fmt::Display for PageLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level_name = match self {
            PageLevel::Pml5 => "PML5",
            PageLevel::Pml4 => "PML4",
            PageLevel::Pdp => "PDP",
            PageLevel::Pd => "PD",
            PageLevel::Pt => "PT",
            PageLevel::Pa => "PA",
        };
        write!(f, "{:5}", level_name)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
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
            PageLevel::Pa => Self(va),
            _ => Self((((va >> level.start_bit()) + 1) << level.start_bit()) - 1),
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

    /// This will return the index at the current entry
    /// For example:
    ///                             |      PML5|     PML4| PDP/PML3|  PD/PML2|  PT/PML1|    Physical
    /// va                  = 000000|0000000000|000000000|000000000|000000011|000000000|000000000000
    /// get_index(va, PD)   = 000000011  <------------------------------'
    pub fn get_index(&self, level: PageLevel) -> u64 {
        let va = self.0;
        match level {
            PageLevel::Pa => panic!("get_index is not expected to be called"),
            _ => (va >> level.start_bit()) & PAGE_INDEX_MASK,
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
            None => panic!("Overflow occurred! {:x} {:x}", self.0, rhs),
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
            None => panic!("Underflow occurred! {:x} {:x}", self.0, rhs),
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
