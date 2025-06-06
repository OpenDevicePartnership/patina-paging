use core::{
    fmt::{self, Display, Formatter},
    ops::{Add, Sub},
};

use crate::{PagingType, PtError, PtResult};

// Constants for common sizes.
pub const SIZE_4KB: u64 = 0x1000;
pub const SIZE_2MB: u64 = 0x200000;
pub const SIZE_1GB: u64 = 0x40000000;
pub const SIZE_4GB: u64 = 0x100000000;
pub const SIZE_64GB: u64 = 0x1000000000;
pub const SIZE_512GB: u64 = 0x8000000000;
pub const SIZE_1TB: u64 = 0x10000000000;
pub const SIZE_4TB: u64 = 0x400000000000;
pub const SIZE_16TB: u64 = 0x100000000000;
pub const SIZE_256TB: u64 = 0x1000000000000;

/// Size of a page in bytes. This assumes a 4KB page size which is currently all
/// that is supported by this crate.
pub const PAGE_SIZE: u64 = SIZE_4KB;

/// Page index mask for 4KB pages with 64-bit page table entries.
const PAGE_INDEX_MASK: u64 = 0x1FF;

// The self map index is used to map the page table itself. For simplicity, we choose the final index of the top
// level page table. This does not conflict with any identity mapping, as the final index of the top level page table
// maps beyond the physically addressable memory.
pub(crate) const SELF_MAP_INDEX: u64 = 0x1FF;

// The zero VA index is used to create a VA range that is used to zero pages before putting them in the page table,
// to ensure break before make semantics. We cannot use the identity mapping because it does not exist. The
// penultimate index in the top level page table is chosen because it also falls outside of physically addressable
// address space and will not conflict with identity mapping.
pub(crate) const ZERO_VA_INDEX: u64 = 0x1FE;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum PageLevel {
    Level5,
    Level4,
    Level3,
    Level2,
    Level1,
}

impl PageLevel {
    pub fn next_level(&self) -> Option<PageLevel> {
        match self {
            PageLevel::Level5 => Some(PageLevel::Level4),
            PageLevel::Level4 => Some(PageLevel::Level3),
            PageLevel::Level3 => Some(PageLevel::Level2),
            PageLevel::Level2 => Some(PageLevel::Level1),
            PageLevel::Level1 => None,
        }
    }

    pub fn is_lowest_level(&self) -> bool {
        matches!(self, PageLevel::Level1)
    }

    pub fn start_bit(&self) -> u64 {
        // This currently assumes a 4kb page size and 64-bit page table entries.
        match self {
            PageLevel::Level5 => 48,
            PageLevel::Level4 => 39,
            PageLevel::Level3 => 30,
            PageLevel::Level2 => 21,
            PageLevel::Level1 => 12,
        }
    }

    pub fn entry_va_size(&self) -> u64 {
        1 << self.start_bit()
    }

    pub fn root_level(paging_type: PagingType) -> PageLevel {
        match paging_type {
            PagingType::Paging5Level => PageLevel::Level5,
            PagingType::Paging4Level => PageLevel::Level4,
        }
    }

    pub fn depth(&self) -> usize {
        match self {
            PageLevel::Level5 => 0,
            PageLevel::Level4 => 1,
            PageLevel::Level3 => 2,
            PageLevel::Level2 => 3,
            PageLevel::Level1 => 4,
        }
    }

    pub fn height(&self) -> usize {
        match self {
            PageLevel::Level5 => 4,
            PageLevel::Level4 => 3,
            PageLevel::Level3 => 2,
            PageLevel::Level2 => 1,
            PageLevel::Level1 => 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct VirtualAddress(u64);
impl VirtualAddress {
    pub fn new(va: u64) -> Self {
        Self(va)
    }

    /// This will return the max va addressable by the current entry
    pub fn round_up(&self, level: PageLevel) -> VirtualAddress {
        let va = self.0;
        let mask = level.entry_va_size() - 1;
        let va = va & !mask;
        let va = va | mask;
        Self(va)
    }

    /// This will return the next virtual address that is aligned to the current entry.
    /// If the next address overflows, it will return the maximum virtual address, which occurs when querying the
    /// self map.
    pub fn get_next_va(&self, level: PageLevel) -> PtResult<VirtualAddress> {
        self.round_up(level).add(1)
    }

    /// This will return the index at the current entry.
    pub fn get_index(&self, level: PageLevel) -> u64 {
        let va = self.0;
        (va >> level.start_bit()) & PAGE_INDEX_MASK
    }

    pub fn is_level_aligned(&self, level: PageLevel) -> bool {
        let va = self.0;
        va & (level.entry_va_size() - 1) == 0
    }

    pub fn is_page_aligned(&self) -> bool {
        let va: u64 = self.0;
        (va & (PAGE_SIZE - 1)) == 0
    }

    pub fn min(lhs: VirtualAddress, rhs: VirtualAddress) -> VirtualAddress {
        VirtualAddress(core::cmp::min(lhs.0, rhs.0))
    }

    /// This will return the range length between self and end (inclusive)
    /// In the case of underflow, it will return 0
    pub fn length_through(&self, end: VirtualAddress) -> PtResult<u64> {
        match end.0.checked_sub(self.0) {
            Some(result) => Ok(result + 1),
            None => Err(PtError::SubtractionUnderflow),
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
    type Output = PtResult<Self>;

    fn add(self, rhs: u64) -> Self::Output {
        match self.0.checked_add(rhs) {
            Some(result) => Ok(VirtualAddress(result)),
            None => Err(PtError::AdditionOverflow),
        }
    }
}

impl Sub<u64> for VirtualAddress {
    type Output = PtResult<Self>;

    fn sub(self, rhs: u64) -> Self::Output {
        match self.0.checked_sub(rhs) {
            Some(result) => Ok(VirtualAddress(result)),
            None => Err(PtError::SubtractionUnderflow),
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

    pub fn is_page_aligned(&self) -> bool {
        let va: u64 = self.0;
        (va & (PAGE_SIZE - 1)) == 0
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
