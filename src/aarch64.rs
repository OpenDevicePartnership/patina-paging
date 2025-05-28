#[allow(unused_imports)]
use core::arch::asm;

use pagetablestore::AArch64PageTableEntry;
use structs::{MAX_VA_4_LEVEL, ZERO_VA_4_LEVEL};

use crate::{
    MemoryAttributes, PageTable, PagingType, PtError, PtResult,
    arch::PageTableHal,
    page_allocator::PageAllocator,
    paging::PageTableInternal,
    structs::{VirtualAddress, *},
};

mod pagetablestore;
mod reg;
mod structs;
#[cfg(test)]
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

impl<P: PageAllocator> PageTable for AArch64PageTable<P> {
    fn map_memory_region(
        &mut self,
        address: u64,
        size: u64,
        attributes: crate::MemoryAttributes,
    ) -> crate::PtResult<()> {
        self.internal.map_memory_region(address, size, attributes)
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> crate::PtResult<()> {
        self.internal.unmap_memory_region(address, size)
    }

    fn remap_memory_region(
        &mut self,
        address: u64,
        size: u64,
        attributes: crate::MemoryAttributes,
    ) -> crate::PtResult<()> {
        self.internal.remap_memory_region(address, size, attributes)
    }

    fn install_page_table(&mut self) -> crate::PtResult<()> {
        self.internal.install_page_table()
    }

    fn query_memory_region(&self, address: u64, size: u64) -> crate::PtResult<crate::MemoryAttributes> {
        self.internal.query_memory_region(address, size)
    }

    fn dump_page_tables(&self, address: u64, size: u64) {
        self.internal.dump_page_tables(address, size)
    }
}

pub(crate) struct PageTableArchAArch64;

impl PageTableHal for PageTableArchAArch64 {
    type PTE = AArch64PageTableEntry;
    const DEFAULT_ATTRIBUTES: MemoryAttributes = MemoryAttributes::Writeback;

    unsafe fn zero_page(base: VirtualAddress) {
        unsafe { reg::zero_page(base.into()) };
    }

    fn paging_type_supported(paging_type: crate::PagingType) -> crate::PtResult<()> {
        match paging_type {
            crate::PagingType::Paging4Level => Ok(()),
            _ => Err(PtError::UnsupportedPagingType),
        }
    }

    fn get_zero_va(paging_type: crate::PagingType) -> crate::PtResult<VirtualAddress> {
        match paging_type {
            crate::PagingType::Paging4Level => Ok(ZERO_VA_4_LEVEL.into()),
            _ => Err(PtError::UnsupportedPagingType),
        }
    }

    fn invalidate_tlb(va: VirtualAddress) {
        reg::update_translation_table_entry(0, va.into());
    }

    fn get_max_va(page_type: crate::PagingType) -> crate::PtResult<VirtualAddress> {
        match page_type {
            crate::PagingType::Paging4Level => Ok(MAX_VA_4_LEVEL.into()),
            _ => Err(PtError::UnsupportedPagingType),
        }
    }

    fn is_table_active(base: u64) -> bool {
        reg::is_this_page_table_active(base.into())
    }

    unsafe fn install_page_table(base: u64) -> crate::PtResult<()> {
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
        if exception_level == 1 {
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
            log::error!("Unsupported max physical address size: {:#x}", max_address);
            return Err(PtError::InvalidParameter);
        };

        let tcr = match exception_level {
            2 => TCR_EL2_DEFAULTS | (tcr_ps << TCR_EL2_PS_SHIFT),
            1 => TCR_EL1_DEFAULTS | (tcr_ps << TCR_EL1_IPS_SHIFT),
            _ => {
                log::error!("Unsupported exception level: {}", exception_level);
                return Err(PtError::InvalidParameter);
            }
        };

        log::info!("Setting TCR: {:#x}", tcr);

        // Set TCR
        reg::set_tcr(tcr);

        // EFI_MEMORY_UC ==> MAIR_ATTR_DEVICE_MEMORY
        // EFI_MEMORY_WC ==> MAIR_ATTR_NORMAL_MEMORY_NON_CACHEABLE
        // EFI_MEMORY_WT ==> MAIR_ATTR_NORMAL_MEMORY_WRITE_THROUGH
        // EFI_MEMORY_WB ==> MAIR_ATTR_NORMAL_MEMORY_WRITE_BACK
        reg::set_mair((0x44 << 8) | (0xBB << 16) | (0xFF << 24));

        // Set TTBR0
        reg::set_ttbr0(base);

        if !reg::is_mmu_enabled() {
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
}
