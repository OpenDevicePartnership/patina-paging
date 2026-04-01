//! AArch64-specific implementation of page table management, including address translation and memory attribute
//! handling.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use reg::ExceptionLevel;
use structs::*;

use crate::{
    MemoryAttributes, PageTable, PagingType, PtError,
    arch::PageTableHal,
    page_allocator::PageAllocator,
    paging::PageTableInternal,
    structs::{VirtualAddress, *},
};

mod reg;
mod structs;
#[cfg(test)]
#[coverage(off)]
mod tests;

const MAX_VA_BITS: u64 = 48;

/// Bits that are reserved and should be set to 1 in the TCR_EL2 register.
const TCR_EL2_RES1_BITS: u64 = (1 << 31) | (1 << 23);

const TCR_EL2_PS_SHIFT: u64 = 16;

const TCR_EL1_IPS_SHIFT: u64 = 32;

const TCR_EL1_TG1_16KB: u64 = 1 << 30;

const TCR_EL1_ED1: u64 = 1 << 23;

const TCR_SH0_INNER_SHAREABLE: u64 = 0b11 << 12;

// TCR Outer cacheability attributes
const TCR_ORGN0_WB_WA: u64 = 1 << 10;

// TCR Inner cacheability attributes
const TCR_IRGN0_WB_WA: u64 = 1 << 8;

// TCR Physical Address Size bits (PS/IPS)
const TCR_PS_4GB: u64 = 0;
const TCR_PS_64GB: u64 = 1;
const TCR_PS_1TB: u64 = 2;
const TCR_PS_4TB: u64 = 3;
const TCR_PS_16TB: u64 = 4;
const TCR_PS_256TB: u64 = 5;

/// TCR_EL2.T0SZ defines the size of the VA space addressed by TTBR0_EL2. The VA space size is 2^(64 - t0sz) bytes.
/// We always want to set the minimum size of TCR_EL2.T0SZ to 16, which gives us a 48-bit VA space. This allows
/// us to use the self map beyond PA space (depending on platform)
const TCR_T0SZ_48_BIT_VA: u64 = 16;

/// Default TCR_EL2 with 48-bit VA space.
const TCR_EL2_DEFAULTS: u64 =
    TCR_ORGN0_WB_WA | TCR_IRGN0_WB_WA | TCR_SH0_INNER_SHAREABLE | TCR_EL2_RES1_BITS | TCR_T0SZ_48_BIT_VA;

/// Default TCR_EL1 with 48-bit VA space.
///
/// Due to Cortex-A57 erratum 822227 we must set TG1[1] == 1, regardless of EPD1.
const TCR_EL1_DEFAULTS: u64 =
    TCR_ORGN0_WB_WA | TCR_IRGN0_WB_WA | TCR_SH0_INNER_SHAREABLE | TCR_T0SZ_48_BIT_VA | TCR_EL1_TG1_16KB | TCR_EL1_ED1;

pub struct AArch64PageTable<P: PageAllocator> {
    internal: PageTableInternal<P, PageTableArchAArch64>,
}

impl<P: PageAllocator> AArch64PageTable<P> {
    pub fn new(page_allocator: P, paging_type: PagingType) -> Result<Self, PtError> {
        if paging_type == PagingType::Paging5Level {
            return Err(PtError::UnsupportedPagingType);
        }
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
    pub unsafe fn from_existing(base: u64, page_allocator: P, paging_type: PagingType) -> Result<Self, PtError> {
        let internal = unsafe { PageTableInternal::from_existing(base, page_allocator, paging_type)? };
        Ok(Self { internal })
    }

    /// Consumes the page table structure and returns the page table root.
    pub fn into_page_table_root(self) -> u64 {
        self.internal.into_page_table_root()
    }

    /// Opens a page table manager for the currently active page tables.
    ///
    /// This reads the current TTBR0 register to determine the active page table
    /// root and reads TCR.T0SZ to detect whether 4-level or 5-level paging is
    /// active.
    ///
    /// # Safety
    ///
    /// This is unsafe because it creates a second manager for the currently
    /// active page tables. The caller must ensure that no other code modifies
    /// the page tables while this manager is in use.
    ///
    /// Additionally, the caller is responsible for ensuring that paging is enabled
    /// and the page table is a completely valid structure.
    ///
    #[coverage(off)] // This requires hardware for meaningful testing.
    pub unsafe fn open_active(page_allocator: P) -> Result<Self, PtError> {
        let base = reg::get_ttbr0();
        let paging_type = detect_paging_type()?;
        // SAFETY: The caller guarantees that the base from TTBR0 is valid and
        // no concurrent modification will occur.
        unsafe { Self::from_existing(base, page_allocator, paging_type) }
    }
}

/// Detect whether 4-level or 5-level paging is active by reading TCR.T0SZ.
#[coverage(off)] // This requires hardware for meaningful testing.
fn detect_paging_type() -> Result<PagingType, PtError> {
    let tcr = reg::get_tcr();
    let tg0 = (tcr >> 14) & 0b11; // TG0 is bits [15:14]
    if tg0 != 0 {
        // Only 4kb granularity is supported
        return Err(PtError::UnsupportedPagingType);
    }

    let t0sz = tcr & 0x3F; // T0SZ is bits [5:0]
    let va_bits = 64 - t0sz;

    match va_bits {
        40..=48 => Ok(PagingType::Paging4Level),
        49..=52 => Ok(PagingType::Paging5Level),
        _ => Err(PtError::UnsupportedPagingType),
    }
}

impl<P: PageAllocator> PageTable for AArch64PageTable<P> {
    fn map_memory_region(
        &mut self,
        address: u64,
        size: u64,
        attributes: crate::MemoryAttributes,
    ) -> Result<(), PtError> {
        self.internal.map_memory_region(address, size, attributes)
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> Result<(), PtError> {
        self.internal.unmap_memory_region(address, size)
    }

    fn install_page_table(&mut self) -> Result<(), PtError> {
        self.internal.install_page_table()
    }

    fn query_memory_region(&self, address: u64, size: u64) -> Result<crate::MemoryAttributes, PtError> {
        self.internal.query_memory_region(address, size)
    }

    fn dump_page_tables(&self, address: u64, size: u64) -> Result<(), PtError> {
        self.internal.dump_page_tables(address, size)
    }
}

pub(crate) struct PageTableArchAArch64;

impl PageTableHal for PageTableArchAArch64 {
    type PTE = PageTableEntryAArch64;
    const DEFAULT_ATTRIBUTES: MemoryAttributes = MemoryAttributes::Writeback;
    const MAX_ENTRIES: usize = (PAGE_SIZE / 8) as usize;

    /// SAFETY: This function is unsafe because it directly manipulates the page table memory at the given base address
    /// to zero it. The caller must ensure that the base address is valid and points to a page table that can be
    /// safely zeroed.
    unsafe fn zero_page(base: VirtualAddress) {
        unsafe { reg::zero_page(base.into()) };
    }

    fn paging_type_supported(paging_type: crate::PagingType) -> Result<(), PtError> {
        match paging_type {
            crate::PagingType::Paging4Level | crate::PagingType::Paging5Level => Ok(()),
        }
    }

    fn get_zero_va(paging_type: crate::PagingType) -> Result<VirtualAddress, PtError> {
        match paging_type {
            crate::PagingType::Paging4Level => Ok(ZERO_VA_4_LEVEL.into()),
            crate::PagingType::Paging5Level => Err(PtError::UnsupportedPagingType),
        }
    }

    fn invalidate_tlb(va: VirtualAddress) {
        reg::update_translation_table_entry(0, va.into());
    }

    fn get_max_va(page_type: crate::PagingType) -> Result<VirtualAddress, PtError> {
        match page_type {
            crate::PagingType::Paging4Level => Ok(MAX_VA_4_LEVEL.into()),
            crate::PagingType::Paging5Level => Ok(MAX_VA_5_LEVEL.into()),
        }
    }

    fn is_table_active(base: u64) -> bool {
        reg::is_this_page_table_active(base.into())
    }

    /// SAFETY: This function is unsafe because it updates the HW page table registers to install a new page table.
    /// The caller must ensure that the base address is valid and points to a properly constructed page table.
    #[coverage(off)] // This manipulates hardware registers that can't be meaningfully tested.
    unsafe fn install_page_table(base: u64, paging_type: PagingType) -> Result<(), PtError> {
        if paging_type != PagingType::Paging4Level {
            log::error!("Only 4-level page tables are supported on AArch64");
            return Err(PtError::UnsupportedPagingType);
        }

        // This step will need to configure the MMU and then activate it on the newly created table.

        if !reg::is_mmu_enabled() {
            // Building the page tables with the MMU is currently not tested.
            // There is no technical limitation for supporting this but creating
            // complex memory structures like the page tables is risky when the
            // MMU is disabled as previously populated cache lines may be written
            // back to memory, overwriting parts of the structure. This can be
            // solved with careful cache management, but until this is implemented
            // and tested, log a warning.
            log::warn!("Building page tables with MMU disabled is untested!");
        }

        // Log a warning for EL1 support until it is properly tested.
        let exception_level = reg::get_current_el();
        if exception_level == ExceptionLevel::EL1 {
            log::warn!("EL1 paging support is untested!");
        }

        let pa_bits = reg::get_phys_addr_bits();
        let max_address_bits = core::cmp::min(pa_bits, MAX_VA_BITS);
        let max_address = (1 << max_address_bits) - 1;
        let tcr_ps = if max_address < SIZE_4GB {
            TCR_PS_4GB
        } else if max_address < SIZE_64GB {
            TCR_PS_64GB
        } else if max_address < SIZE_1TB {
            TCR_PS_1TB
        } else if max_address < SIZE_4TB {
            TCR_PS_4TB
        } else if max_address < SIZE_16TB {
            TCR_PS_16TB
        } else if max_address < SIZE_256TB {
            TCR_PS_256TB
        } else {
            log::error!("Unsupported max physical address size: {max_address:#x}");
            return Err(PtError::InvalidParameter);
        };

        let tcr = match exception_level {
            ExceptionLevel::EL2 => TCR_EL2_DEFAULTS | (tcr_ps << TCR_EL2_PS_SHIFT),
            ExceptionLevel::EL1 => TCR_EL1_DEFAULTS | (tcr_ps << TCR_EL1_IPS_SHIFT),
        };

        log::info!("Setting TCR: {tcr:#x}");

        // If the MMU is already enabled and the paging type is changing, we must
        // disable the MMU before updating TCR and TTBR0 because these registers
        // cannot be changed atomically. Modifying them with the MMU on while the
        // paging level changes would cause a translation fault.
        let mmu_was_enabled = reg::is_mmu_enabled();
        let paging_type_changing = if mmu_was_enabled { detect_paging_type().ok() != Some(paging_type) } else { false };

        if paging_type_changing {
            log::info!("Paging type is changing, disabling MMU for TCR/TTBR0 update");
            // SAFETY: The caller of install_page_table guarantees that the
            // current code and data are identity-mapped.
            unsafe { reg::disable_mmu() };
        }

        // Set TCR
        reg::set_tcr(tcr);

        // EFI_MEMORY_UC ==> MAIR_ATTR_DEVICE_MEMORY
        // EFI_MEMORY_WC ==> MAIR_ATTR_NORMAL_MEMORY_NON_CACHEABLE
        // EFI_MEMORY_WT ==> MAIR_ATTR_NORMAL_MEMORY_WRITE_THROUGH
        // EFI_MEMORY_WB ==> MAIR_ATTR_NORMAL_MEMORY_WRITE_BACK
        reg::set_mair((0x44 << 8) | (0xBB << 16) | (0xFF << 24));

        // Set TTBR0
        reg::set_ttbr0(base);

        if !mmu_was_enabled || paging_type_changing {
            reg::set_alignment_check(false);
            reg::set_stack_alignment_check(true);
            reg::enable_instruction_cache();
            reg::enable_data_cache();

            reg::enable_mmu();
        }

        Ok(())
    }

    fn level_supports_pa_entry(level: PageLevel) -> bool {
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
                PageLevel::Level5 => unimplemented!(),
                PageLevel::Level4 => FOUR_LEVEL_LEVEL4_SELF_MAP_BASE,
                PageLevel::Level3 => FOUR_LEVEL_LEVEL3_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PageLevel::Level4)),
                PageLevel::Level2 => {
                    FOUR_LEVEL_LEVEL2_SELF_MAP_BASE
                        + (SIZE_2MB * va.get_index(PageLevel::Level4))
                        + (SIZE_4KB * va.get_index(PageLevel::Level3))
                }
                PageLevel::Level1 => {
                    FOUR_LEVEL_LEVEL1_SELF_MAP_BASE
                        + (SIZE_1GB * va.get_index(PageLevel::Level4))
                        + (SIZE_2MB * va.get_index(PageLevel::Level3))
                        + (SIZE_4KB * va.get_index(PageLevel::Level2))
                }
            },
            PagingType::Paging5Level => unimplemented!("5-level self-map not supported on AArch64"),
        }
    }

    fn invalidate_tlb_all() {
        reg::invalidate_tlb();
    }
}
#[cfg(test)]
mod hal_tests {
    use super::*;
    use crate::{page_allocator::PageAllocatorStub, structs::PageLevel};

    #[test]
    fn test_paging_type_supported() {
        assert!(PageTableArchAArch64::paging_type_supported(PagingType::Paging4Level).is_ok());
        assert!(PageTableArchAArch64::paging_type_supported(PagingType::Paging5Level).is_ok());
    }

    #[test]
    fn test_get_zero_va() {
        assert_eq!(PageTableArchAArch64::get_zero_va(PagingType::Paging4Level).unwrap(), ZERO_VA_4_LEVEL.into());
        assert!(PageTableArchAArch64::get_zero_va(PagingType::Paging5Level).is_err());
    }

    #[test]
    fn test_get_max_va() {
        assert_eq!(PageTableArchAArch64::get_max_va(PagingType::Paging4Level).unwrap(), MAX_VA_4_LEVEL.into());
        assert_eq!(PageTableArchAArch64::get_max_va(PagingType::Paging5Level).unwrap(), MAX_VA_5_LEVEL.into());
    }

    #[test]
    fn test_level_supports_pa_entry() {
        assert!(!PageTableArchAArch64::level_supports_pa_entry(PageLevel::Level5));
        assert!(!PageTableArchAArch64::level_supports_pa_entry(PageLevel::Level4));
        assert!(PageTableArchAArch64::level_supports_pa_entry(PageLevel::Level3));
        assert!(PageTableArchAArch64::level_supports_pa_entry(PageLevel::Level2));
        assert!(PageTableArchAArch64::level_supports_pa_entry(PageLevel::Level1));
    }

    #[test]
    fn test_cannot_create_5_level_page_table() {
        let res = AArch64PageTable::new(PageAllocatorStub::new(), PagingType::Paging5Level);
        assert!(res.is_err());
        assert_eq!(res.err().unwrap(), PtError::UnsupportedPagingType);
    }

    #[test]
    fn test_get_self_mapped_base_4_level() {
        let va: VirtualAddress = 0u64.into();
        assert_eq!(
            PageTableArchAArch64::get_self_mapped_base(PageLevel::Level4, va, PagingType::Paging4Level),
            FOUR_LEVEL_LEVEL4_SELF_MAP_BASE
        );
        assert_eq!(
            PageTableArchAArch64::get_self_mapped_base(PageLevel::Level3, va, PagingType::Paging4Level),
            FOUR_LEVEL_LEVEL3_SELF_MAP_BASE
        );
        assert_eq!(
            PageTableArchAArch64::get_self_mapped_base(PageLevel::Level2, va, PagingType::Paging4Level),
            FOUR_LEVEL_LEVEL2_SELF_MAP_BASE
        );
        assert_eq!(
            PageTableArchAArch64::get_self_mapped_base(PageLevel::Level1, va, PagingType::Paging4Level),
            FOUR_LEVEL_LEVEL1_SELF_MAP_BASE
        );
    }
}
