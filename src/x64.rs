//! x64-specific implementation of page table management, including paging structures and address translation.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
#[allow(unused_imports)]
use core::arch::asm;
use core::ptr;

mod structs;
#[cfg(test)]
#[coverage(off)]
mod tests;

use structs::{CR3_PAGE_BASE_ADDRESS_MASK, MAX_VA_4_LEVEL, MAX_VA_5_LEVEL, ZERO_VA_4_LEVEL, ZERO_VA_5_LEVEL};

use crate::{
    MemoryAttributes, PageTable, PagingType, PtResult,
    arch::PageTableHal,
    page_allocator::PageAllocator,
    paging::PageTableInternal,
    structs::{PAGE_SIZE, PageLevel, SIZE_1GB, SIZE_2MB, SIZE_4KB, SIZE_512GB, VirtualAddress},
    x64::structs::*,
};

// Constants for page levels to conform to x64 standards.
pub const PML5: PageLevel = PageLevel::Level5;
pub const PML4: PageLevel = PageLevel::Level4;
pub const PDP: PageLevel = PageLevel::Level3;
pub const PD: PageLevel = PageLevel::Level2;
pub const PT: PageLevel = PageLevel::Level1;

// Maximum number of entries in a page table (512)
pub const MAX_ENTRIES: usize = (PAGE_SIZE / 8) as usize;

pub struct X64PageTable<P: PageAllocator> {
    internal: PageTableInternal<P, PageTableArchX64>,
}

impl<P: PageAllocator> X64PageTable<P> {
    pub fn new(page_allocator: P, paging_type: PagingType) -> PtResult<Self> {
        let internal = PageTableInternal::new(page_allocator, paging_type)?;
        Ok(Self { internal })
    }

    /// Create a page table from existing page table base. This can be used to
    /// parse or edit an existing identity mapped page table.
    ///
    /// # Safety
    ///
    /// This routine will return a struct that will parse memory addresses from
    /// PFNs in the provided base, so that caller is responsible for ensuring
    /// safety of that base.
    ///
    pub unsafe fn from_existing(base: u64, page_allocator: P, paging_type: PagingType) -> PtResult<Self> {
        let internal = unsafe { PageTableInternal::from_existing(base, page_allocator, paging_type)? };
        Ok(Self { internal })
    }

    /// Consumes the page table structure and returns the page table root.
    pub fn into_page_table_root(self) -> u64 {
        self.internal.into_page_table_root()
    }
}

impl<P: PageAllocator> PageTable for X64PageTable<P> {
    fn map_memory_region(
        &mut self,
        address: u64,
        size: u64,
        attributes: crate::MemoryAttributes,
    ) -> crate::PtResult<()> {
        check_canonical_range(address, size, self.internal.paging_type)?;
        self.internal.map_memory_region(address, size, attributes)
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> crate::PtResult<()> {
        check_canonical_range(address, size, self.internal.paging_type)?;
        self.internal.unmap_memory_region(address, size)
    }

    fn remap_memory_region(
        &mut self,
        address: u64,
        size: u64,
        attributes: crate::MemoryAttributes,
    ) -> crate::PtResult<()> {
        check_canonical_range(address, size, self.internal.paging_type)?;
        self.internal.remap_memory_region(address, size, attributes)
    }

    fn install_page_table(&mut self) -> crate::PtResult<()> {
        self.internal.install_page_table()
    }

    fn query_memory_region(&self, address: u64, size: u64) -> crate::PtResult<crate::MemoryAttributes> {
        check_canonical_range(address, size, self.internal.paging_type)?;
        self.internal.query_memory_region(address, size)
    }

    fn dump_page_tables(&self, address: u64, size: u64) -> PtResult<()> {
        self.internal.dump_page_tables(address, size)
    }
}

pub(crate) fn invalidate_tlb(va: VirtualAddress) {
    let _va: u64 = va.into();
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it. In this case we are invalidating
    // the TLB, which is a safe operation.
    #[cfg(all(not(test), target_arch = "x86_64"))]
    unsafe {
        core::arch::asm!("mfence", "invlpg [{0}]", in(reg) _va)
    };
}

pub(crate) struct PageTableArchX64;

impl PageTableHal for PageTableArchX64 {
    type PTE = PageTableEntryX64;
    const DEFAULT_ATTRIBUTES: MemoryAttributes = MemoryAttributes::empty();
    const MAX_ENTRIES: usize = MAX_ENTRIES;

    /// Zero a page of memory
    ///
    /// # Safety
    /// This function is unsafe because it operates on raw pointers. It requires the caller to ensure the VA passed in
    /// is mapped.
    unsafe fn zero_page(page: VirtualAddress) {
        // This cast must occur as a mutable pointer to a u8, as otherwise the compiler can optimize out the write,
        // which must not happen as that would violate break before make and have garbage in the page table.
        unsafe { ptr::write_bytes(Into::<u64>::into(page) as *mut u8, 0, PAGE_SIZE as usize) };
    }

    fn paging_type_supported(paging_type: PagingType) -> PtResult<()> {
        match paging_type {
            PagingType::Paging5Level => Ok(()),
            PagingType::Paging4Level => Ok(()),
        }
    }

    fn get_zero_va(paging_type: PagingType) -> PtResult<VirtualAddress> {
        match paging_type {
            PagingType::Paging5Level => Ok(ZERO_VA_5_LEVEL.into()),
            PagingType::Paging4Level => Ok(ZERO_VA_4_LEVEL.into()),
        }
    }

    fn invalidate_tlb(va: VirtualAddress) {
        invalidate_tlb(va);
    }

    fn get_max_va(paging_type: PagingType) -> PtResult<VirtualAddress> {
        match paging_type {
            PagingType::Paging5Level => Ok(MAX_VA_5_LEVEL.into()),
            PagingType::Paging4Level => Ok(MAX_VA_4_LEVEL.into()),
        }
    }

    fn is_table_active(base: u64) -> bool {
        read_cr3() == (base & CR3_PAGE_BASE_ADDRESS_MASK)
    }

    /// SAFETY: This function is unsafe because it updates the HW page table registers to install a new page table.
    /// The caller must ensure that the base address is valid and points to a properly constructed page table.
    unsafe fn install_page_table(base: u64) -> PtResult<()> {
        unsafe {
            write_cr3(base);
        }
        Ok(())
    }

    fn level_supports_pa_entry(level: crate::structs::PageLevel) -> bool {
        matches!(level, PageLevel::Level3 | PageLevel::Level2 | PageLevel::Level1)
    }

    /// This function returns the base address of the self-mapped page table at the given level for this VA
    /// It is used in the get_entry function to determine the base address in the self map in which to apply
    /// the index within the page table to get the entry we are intending to operate on.
    /// Each index within the VA is multiplied by the memory size that each entry in the page table at that
    /// level covers in order to calculate the correct address. E.g., for a 4-level page table, each PML4 entry
    /// covers 512GB of memory, each PDP entry covers 1GB of memory, each PD entry covers 2MB of memory, and
    /// each PT entry covers 4KB of memory, but when we recurse in the self map to a given level, we shift what
    /// each entry covers to be the size of the next level down for each recursion into the self map we did.
    fn get_self_mapped_base(level: PageLevel, va: VirtualAddress, paging_type: PagingType) -> u64 {
        match paging_type {
            PagingType::Paging4Level => match level {
                // PML5 is not used in 4-level paging, so we return an unimplemented error.
                PML5 => unimplemented!(),
                PML4 => FOUR_LEVEL_PML4_SELF_MAP_BASE,
                PDP => FOUR_LEVEL_PDP_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PML4)),
                PD => FOUR_LEVEL_PD_SELF_MAP_BASE + (SIZE_2MB * va.get_index(PML4)) + (SIZE_4KB * va.get_index(PDP)),
                PT => {
                    FOUR_LEVEL_PT_SELF_MAP_BASE
                        + (SIZE_1GB * va.get_index(PML4))
                        + (SIZE_2MB * va.get_index(PDP))
                        + (SIZE_4KB * va.get_index(PD))
                }
            },
            PagingType::Paging5Level => match level {
                PML5 => FIVE_LEVEL_PML5_SELF_MAP_BASE,
                PML4 => FIVE_LEVEL_PML4_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PML5)),
                PDP => FIVE_LEVEL_PDP_SELF_MAP_BASE + (SIZE_2MB * va.get_index(PML5)) + (SIZE_4KB * va.get_index(PML4)),
                PD => {
                    FIVE_LEVEL_PD_SELF_MAP_BASE
                        + (SIZE_1GB * va.get_index(PML5))
                        + (SIZE_2MB * va.get_index(PML4))
                        + (SIZE_4KB * va.get_index(PDP))
                }
                PT => {
                    FIVE_LEVEL_PT_SELF_MAP_BASE
                        + (SIZE_512GB * va.get_index(PML5))
                        + (SIZE_1GB * va.get_index(PML4))
                        + (SIZE_2MB * va.get_index(PDP))
                        + (SIZE_4KB * va.get_index(PD))
                }
            },
        }
    }
}

/// Write CR3 register. Also invalidates TLB.
///
/// # Safety
/// This function is unsafe because it updates the HW page table registers to install a new page table. The
/// caller must ensure that the base address is valid and points to a properly constructed page table.
unsafe fn write_cr3(_value: u64) {
    #[cfg(all(not(test), target_arch = "x86_64"))]
    {
        unsafe {
            asm!("mov cr3, {}", in(reg) _value, options(nostack, preserves_flags));
        }
    }
}

/// Read CR3 register.
fn read_cr3() -> u64 {
    let mut _value = 0u64;

    #[cfg(all(not(test), target_arch = "x86_64"))]
    {
        // SAFETY: inline asm is inherently unsafe because Rust can't reason about it.
        // In this case we are reading the CR3 register, which is a safe operation.
        unsafe {
            asm!("mov {}, cr3", out(reg) _value, options(nostack, preserves_flags));
        }
    }

    _value
}

/// Checks if the given address is canonical.
fn check_canonical_range(address: u64, size: u64, paging_type: PagingType) -> PtResult<()> {
    // For a canonical address, the bits 63 though the max bit supported by the
    // paging type must be all 0s or all 1s. Get the mask for this range.
    let max_bit = paging_type.linear_address_bits() - 1;
    let mask = u64::MAX << max_bit;

    if (address & mask) != 0 && (address & mask) != mask {
        return Err(crate::PtError::InvalidParameter);
    }

    // Check that the end address is also canonical without spanning non-canonical addresses.
    let size = size.checked_sub(1).ok_or(crate::PtError::InvalidMemoryRange)?;
    let end_address = address.checked_add(size).ok_or(crate::PtError::InvalidMemoryRange)?;
    if (end_address & mask) != (address & mask) {
        return Err(crate::PtError::InvalidMemoryRange);
    }

    Ok(())
}

#[cfg(test)]
mod unittests {
    use super::*;
    use crate::structs::VirtualAddress;

    #[test]
    fn test_zero_page_zeros_entire_page() {
        // Allocate a page-sized Vec<u8> and fill it with non-zero values
        let mut page = vec![0xAAu8; PAGE_SIZE as usize];
        let va = VirtualAddress::new(page.as_mut_ptr() as u64);

        // SAFETY: We have exclusive access to the page buffer
        unsafe {
            PageTableArchX64::zero_page(va);
        }

        // Assert all bytes are zero
        assert!(page.iter().all(|&b| b == 0), "Not all bytes were zeroed");
    }

    #[test]
    fn test_check_canonical_range_4_level() {
        let paging_type = PagingType::Paging4Level;

        // Check the full lower address range.
        assert!(check_canonical_range(0x0000_0000_0000_0000, 1 << 47, paging_type).is_ok());

        // Check the full upper address range.
        assert!(check_canonical_range(0xFFFF_8000_0000_0000, 1 << 47, paging_type).is_ok());

        // Check going into the non-canonical range.
        assert!(check_canonical_range(0x0000_7FFF_FFFF_F000, 2 * PAGE_SIZE, paging_type).is_err());

        // Check fully non-canonical range.
        assert!(check_canonical_range(0x8d48_0000_0000_0000, PAGE_SIZE, paging_type).is_err());

        // Checking coming out of the non-canonical range.
        assert!(check_canonical_range(0xFFFF_0000_0000_0000, 0x8F00_0000_0000, paging_type).is_err());

        // Check spanning non-canonical addresses.
        assert!(check_canonical_range(0x0000_0000_0000_0000, 0xFFFF_FFFF_FFFF_F000, paging_type).is_err());
    }

    #[test]
    fn test_check_canonical_range_5_level() {
        let paging_type = PagingType::Paging5Level;

        // Check the full lower address range.
        assert!(check_canonical_range(0x0000_0000_0000_0000, 1 << 56, paging_type).is_ok());

        // Check the full upper address range.
        assert!(check_canonical_range(0xFF00_0000_0000_0000, 1 << 56, paging_type).is_ok());

        // Check going into the non-canonical range.
        assert!(check_canonical_range(0x00FF_FFFF_FFFF_F000, 2 * PAGE_SIZE, paging_type).is_err());

        // Check fully non-canonical range.
        assert!(check_canonical_range(0x8d48_0000_0000_0000, PAGE_SIZE, paging_type).is_err());

        // Checking coming out of the non-canonical range.
        assert!(check_canonical_range(0xFE00_0000_0000_0000, 0x1_FF00_0000_0000, paging_type).is_err());

        // Check spanning non-canonical addresses.
        assert!(check_canonical_range(0x0000_0000_0000_0000, 0xFFFF_FFFF_FFFF_F000, paging_type).is_err());
    }
}
