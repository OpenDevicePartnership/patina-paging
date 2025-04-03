use crate::{MemoryAttributes, PtError, PtResult};
use alloc::string::String;
use bitfield_struct::bitfield;
use core::{
    fmt::{self, Display, Formatter},
    ops::{Add, Sub},
    ptr::write_volatile,
};

pub const PAGE_SIZE: u64 = 0x1000; // 4KB

const PAGE_INDEX_MASK: u64 = 0x1FF;

// The following definitions are the maximum virtual address for each level of the page table hierarchy. These are
// above the range generally supported by processors, but we only care that our zero VA and self-map aren't overwritten
pub(crate) const MAX_VA_5_LEVEL: u64 = 0xFFFD_FFFF_FFFF_FFFF;
pub(crate) const MAX_VA_4_LEVEL: u64 = 0xFFFF_FEFF_FFFF_FFFF;

// The following definitions are the zero VA for each level of the page table hierarchy. These are used to create a
// VA range that is used to zero pages before putting them in the page table. These addresses are calculated as the
// first VA in the penultimate index in the top level page table.
pub(crate) const ZERO_VA_5_LEVEL: u64 = 0xFFFE_0000_0000_0000;
pub(crate) const ZERO_VA_4_LEVEL: u64 = 0xFFFF_FF00_0000_0000;

// The self map index is used to map the page table itself. For simplicity, we choose the final index of the top
// level page table. This does not conflict with any identity mapping, as the final index of the top level page table
// maps beyond the physically addressable memory.
pub(crate) const SELF_MAP_INDEX: u64 = 0x1FF;

// The zero VA index is used to create a VA range that is used to zero pages before putting them in the page table,
// to ensure break before make semantics. We cannot use the identity mapping because it does not exist. The
// penultimate index in the top level page table is chosen because it also falls outside of physically addressable
// address space and will not conflict with identity mapping.
pub(crate) const ZERO_VA_INDEX: u64 = 0x1FE;

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

const PML5_START_BIT: u64 = 48;
const PML4_START_BIT: u64 = 39;
const PDP_START_BIT: u64 = 30;
const PD_START_BIT: u64 = 21;
const PT_START_BIT: u64 = 12;

pub(crate) const CR3_PAGE_BASE_ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000; // 40 bit - lower 12 bits for alignment

pub(crate) const FRAME_SIZE_4KB: u64 = 0x1000; // 4KB
pub(crate) const PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT: u64 = 12u64; // lower 12 bits for alignment
pub(crate) const PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000; // 40 bit - lower 12 bits for alignment

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

impl PageTableEntry {
    /// update all the fields and next table base address
    pub fn update_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress) -> PtResult<()> {
        let mut next_level_table_base: u64 = pa.into();

        next_level_table_base &= PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_MASK;
        next_level_table_base >>= PAGE_TABLE_ENTRY_4KB_PAGE_TABLE_BASE_ADDRESS_SHIFT;

        self.set_page_table_base_address(next_level_table_base);
        self.set_present(true);

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

    /// Performs an overwrite of the table entry. This ensures that all fields
    /// are written to memory at once to avoid partial PTE edits causing unexpected
    /// behavior with speculative execution or when operating on the current mapping.
    pub fn swap(&mut self, other: &Self) {
        unsafe { write_volatile(&mut self.0, other.0) };
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum PageLevel {
    Pml5 = 5,
    Pml4 = 4,
    Pdp = 3,
    Pd = 2,
    Pt = 1,
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
        }
    }

    pub fn entry_va_size(&self) -> u64 {
        1 << self.start_bit()
    }

    pub fn supports_pa_entry(&self) -> bool {
        match self {
            PageLevel::Pt => true,
            // 2MB & 1GB pages could be disabled by a crate feature in the future.
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
        let mask = level.entry_va_size() - 1;
        let va = va & !mask;
        let va = va | mask;
        Self(va)
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
        (va >> level.start_bit()) & PAGE_INDEX_MASK
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
