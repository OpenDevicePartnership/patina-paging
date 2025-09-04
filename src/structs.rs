//! Common data structures and constants for page table management and address translation.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
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

#[derive(PartialEq, Clone, Copy, Debug, Eq, Hash)]
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
            Some(0) => Ok(0),
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

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;

    #[test]
    fn test_page_level_next_level() {
        assert_eq!(PageLevel::Level5.next_level(), Some(PageLevel::Level4));
        assert_eq!(PageLevel::Level4.next_level(), Some(PageLevel::Level3));
        assert_eq!(PageLevel::Level3.next_level(), Some(PageLevel::Level2));
        assert_eq!(PageLevel::Level2.next_level(), Some(PageLevel::Level1));
        assert_eq!(PageLevel::Level1.next_level(), None);
    }

    #[test]
    fn test_page_level_is_lowest_level() {
        assert!(!PageLevel::Level5.is_lowest_level());
        assert!(!PageLevel::Level4.is_lowest_level());
        assert!(!PageLevel::Level3.is_lowest_level());
        assert!(!PageLevel::Level2.is_lowest_level());
        assert!(PageLevel::Level1.is_lowest_level());
    }

    #[test]
    fn test_page_level_start_bit_and_entry_va_size() {
        assert_eq!(PageLevel::Level5.start_bit(), 48);
        assert_eq!(PageLevel::Level4.start_bit(), 39);
        assert_eq!(PageLevel::Level3.start_bit(), 30);
        assert_eq!(PageLevel::Level2.start_bit(), 21);
        assert_eq!(PageLevel::Level1.start_bit(), 12);

        assert_eq!(PageLevel::Level5.entry_va_size(), 1 << 48);
        assert_eq!(PageLevel::Level4.entry_va_size(), 1 << 39);
        assert_eq!(PageLevel::Level3.entry_va_size(), 1 << 30);
        assert_eq!(PageLevel::Level2.entry_va_size(), 1 << 21);
        assert_eq!(PageLevel::Level1.entry_va_size(), 1 << 12);
    }

    #[test]
    fn test_page_level_depth_and_height() {
        assert_eq!(PageLevel::Level5.depth(), 0);
        assert_eq!(PageLevel::Level4.depth(), 1);
        assert_eq!(PageLevel::Level3.depth(), 2);
        assert_eq!(PageLevel::Level2.depth(), 3);
        assert_eq!(PageLevel::Level1.depth(), 4);

        assert_eq!(PageLevel::Level5.height(), 4);
        assert_eq!(PageLevel::Level4.height(), 3);
        assert_eq!(PageLevel::Level3.height(), 2);
        assert_eq!(PageLevel::Level2.height(), 1);
        assert_eq!(PageLevel::Level1.height(), 0);
    }

    #[test]
    fn test_virtual_address_get_next_va() {
        let va = VirtualAddress::new(0x1000);
        let next = va.get_next_va(PageLevel::Level1).unwrap();
        assert_eq!(next, VirtualAddress::new(0x2000));

        // Test overflow
        let va = VirtualAddress::new(u64::MAX);
        assert!(va.get_next_va(PageLevel::Level1).is_err());
    }

    #[test]
    fn test_virtual_address_get_index() {
        let va = VirtualAddress::new(0x1234_5678_9ABC_DEF0);
        assert_eq!(va.get_index(PageLevel::Level1), 0x1CD);
        assert_eq!(va.get_index(PageLevel::Level2), 0xD5);
        assert_eq!(va.get_index(PageLevel::Level3), 0x1E2);
        assert_eq!(va.get_index(PageLevel::Level4), 0xAC);
        assert_eq!(va.get_index(PageLevel::Level5), 0x34);
    }

    #[test]
    fn test_virtual_address_is_page_aligned() {
        assert!(VirtualAddress::new(0x1000).is_page_aligned());
        assert!(!VirtualAddress::new(0x1001).is_page_aligned());
    }

    #[test]
    fn test_virtual_address_min() {
        let a = VirtualAddress::new(0x1000);
        let b = VirtualAddress::new(0x2000);
        assert_eq!(VirtualAddress::min(a, b), a);
        assert_eq!(VirtualAddress::min(b, a), a);
    }

    #[test]
    fn test_virtual_address_length_through() {
        let a = VirtualAddress::new(0x1000);
        let b = VirtualAddress::new(0x1FFF);
        assert_eq!(a.length_through(b).unwrap(), 0x1000);

        // Test a longer range
        let a = VirtualAddress::new(0x1000);
        let b = VirtualAddress::new(0x1_0000_0000_0000);
        assert_eq!(a.length_through(b).unwrap(), 0x1_0000_0000_0000 - 0x1000 + 1);

        // Test a range where start == end
        let a = VirtualAddress::new(0xABCDEF);
        let b = VirtualAddress::new(0xABCDEF);
        assert_eq!(a.length_through(b).unwrap(), 0);

        // Test a range with start > end (should error)
        let a = VirtualAddress::new(0x2000);
        let b = VirtualAddress::new(0x1FFF);
        assert!(a.length_through(b).is_err());
    }

    #[test]
    fn test_virtual_address_add_sub() {
        let a = VirtualAddress::new(0x1000);
        assert_eq!(a + 0x1000, Ok(VirtualAddress::new(0x2000)));
        assert_eq!(a - 0x1000, Ok(VirtualAddress::new(0x0)));
        assert!(a - 0x2000 == Err(PtError::SubtractionUnderflow));
        let max = VirtualAddress::new(u64::MAX);
        assert!(max + 1 == Err(PtError::AdditionOverflow));
    }

    #[test]
    fn test_virtual_physical_address_conversion() {
        let va = VirtualAddress::new(0x1234_5678);
        let pa: PhysicalAddress = va.into();
        assert_eq!(pa.0, 0x1234_5678);

        let pa = PhysicalAddress::new(0x8765_4321);
        let va: VirtualAddress = pa.into();
        assert_eq!(va.0, 0x8765_4321);

        // Test conversion symmetry
        let va2: VirtualAddress = pa.into();
        assert_eq!(va, va2);
        let pa2: PhysicalAddress = va.into();
        assert_eq!(pa, pa2);
    }

    #[test]
    fn test_physical_address_is_page_aligned() {
        assert!(PhysicalAddress::new(0x1000).is_page_aligned());
        assert!(!PhysicalAddress::new(0x1001).is_page_aligned());
    }

    #[test]
    fn test_virtual_address_from_and_into_u64() {
        let val = 0xDEADBEEF;
        let va = VirtualAddress::from(val);
        assert_eq!(va.0, val);
        let back: u64 = va.into();
        assert_eq!(back, val);
    }

    #[test]
    fn test_physical_address_from_and_into_u64() {
        let val = 0xCAFEBABE;
        let pa = PhysicalAddress::from(val);
        assert_eq!(pa.0, val);
        let back: u64 = pa.into();
        assert_eq!(back, val);
    }

    #[test]
    fn test_virtual_address_round_up_alignment() {
        let va = VirtualAddress::new(0x1234_5678_9ABC_DEF0);
        let expected = [
            0x1234_5678_9ABC_DFFF, // Level1: 4KB
            0x1234_5678_9ABF_FFFF, // Level2: 2MB
            0x1234_5678_BFFF_FFFF, // Level3: 1GB
            0x1234_567F_FFFF_FFFF, // Level4: 512GB
            0x1234_FFFF_FFFF_FFFF, // Level5: 256TB
        ];
        for (i, level) in
            [PageLevel::Level1, PageLevel::Level2, PageLevel::Level3, PageLevel::Level4, PageLevel::Level5]
                .iter()
                .enumerate()
        {
            let rounded = va.round_up(*level);
            assert_eq!(rounded.0 & (level.entry_va_size() - 1), level.entry_va_size() - 1);
            assert_eq!(rounded.0, expected[i]);
        }
    }

    #[test]
    fn test_virtual_address_is_level_aligned_various() {
        let va = VirtualAddress::new(0x4000);
        assert!(va.is_level_aligned(PageLevel::Level1));
        assert!(!va.is_level_aligned(PageLevel::Level2));
        let va2 = VirtualAddress::new(0x200000);
        assert!(va2.is_level_aligned(PageLevel::Level2));
    }

    #[test]
    fn test_page_level_root_level() {
        assert_eq!(PageLevel::root_level(PagingType::Paging5Level), PageLevel::Level5);
        assert_eq!(PageLevel::root_level(PagingType::Paging4Level), PageLevel::Level4);
    }
}
