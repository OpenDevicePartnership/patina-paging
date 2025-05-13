#[allow(unused_imports)]
use core::arch::asm;

use pagetablestore::AArch64PageTableEntry;
use structs::{MAX_VA_4_LEVEL, ZERO_VA_4_LEVEL};

use crate::{arch::PageTableArch, structs::*, PtError};

mod pagetablestore;
mod reg;
mod structs;

const MAX_VA_BITS: u64 = 48;

pub struct PageTableAarch64;

impl PageTableArch for PageTableAarch64 {
    type PTE = AArch64PageTableEntry;

    unsafe fn zero_page(base: crate::structs::VirtualAddress) {
        reg::zero_page(base.into());
    }

    fn paging_type_supported(paging_type: crate::PagingType) -> crate::PtResult<()> {
        match paging_type {
            crate::PagingType::Paging4Level => Ok(()),
            _ => Err(PtError::UnsupportedPagingType),
        }
    }

    fn get_zero_va(paging_type: crate::PagingType) -> crate::PtResult<crate::structs::VirtualAddress> {
        match paging_type {
            crate::PagingType::Paging4Level => Ok(ZERO_VA_4_LEVEL.into()),
            _ => Err(PtError::UnsupportedPagingType),
        }
    }

    fn invalidate_tlb(va: Option<crate::structs::VirtualAddress>) {
        match va {
            Some(va) => reg::update_translation_table_entry(va.into(), 0),
            None => todo!(),
        }
    }

    fn get_max_va(page_type: crate::PagingType) -> crate::PtResult<crate::structs::VirtualAddress> {
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

        let pa_bits = reg::get_phys_addr_bits();
        let max_address_bits = core::cmp::min(pa_bits, MAX_VA_BITS);
        let max_address = (1 << max_address_bits) - 1;
        let max_address_tcr = if max_address < SIZE_4GB {
            0
        } else if max_address < SIZE_64GB {
            1
        } else if max_address < SIZE_1TB {
            2
        } else if max_address < SIZE_4TB {
            3
        } else if max_address < SIZE_16TB {
            4
        } else if max_address < SIZE_256TB {
            5
        } else {
            return Err(PtError::InvalidParameter);
        };

        // TCR_EL2.T0SZ defines the size of the VA space addressed by TTBR0_EL2. The VA space size is 2^(64 - t0sz) bytes.
        // We always want to set the minimum size of TCR_EL2.T0SZ to 16, which gives us a 48-bit VA space. This allows
        // us to use the self map beyond PA space (depending on platform)
        let t0sz = 16;
        // let root_table_cnt = get_root_table_count(t0sz); // Its not really supported..
        let root_table_cnt = 1;

        let mut tcr: u64;

        if reg::get_current_el() == 2 {
            // Note: Bits 23 and 31 are reserved(RES1) bits in TCR_EL2
            tcr = t0sz | (1 << 31) | (1 << 23);

            // Set the Physical Address Size using MaxAddress
            tcr |= max_address_tcr << 16;
        } else if reg::get_current_el() == 1 {
            // Due to Cortex-A57 erratum #822227 we must set TG1[1] == 1, regardless of EPD1.
            tcr = t0sz | 1 << 30 | 1 << 23;

            // Set the Physical Address Size using MaxAddress
            tcr |= max_address_tcr << 32;
        } else {
            return Err(PtError::InvalidParameter);
        }

        //
        // Translation table walks are always cache coherent on ARMv8-A, so cache
        // maintenance on page tables is never needed. Since there is a risk of
        // loss of coherency when using mismatched attributes, and given that memory
        // is mapped cacheable except for extraordinary cases (such as non-coherent
        // DMA), have the page table walker perform cached accesses as well, and
        // assert below that matches the attributes we use for CPU accesses to
        // the region.
        //
        tcr |= 3 << 12 | 1 << 10 | 1 << 8;

        // Set TCR
        reg::set_tcr(tcr);

        if !reg::is_mmu_enabled() {
            // Make sure we are not inadvertently hitting in the caches
            // when populating the page tables.
            reg::cache_range_operation(base.into(), root_table_cnt * 8, reg::CpuFlushType::EFiCpuFlushTypeInvalidate);
        }

        // EFI_MEMORY_UC ==> MAIR_ATTR_DEVICE_MEMORY
        // EFI_MEMORY_WC ==> MAIR_ATTR_NORMAL_MEMORY_NON_CACHEABLE
        // EFI_MEMORY_WT ==> MAIR_ATTR_NORMAL_MEMORY_WRITE_THROUGH
        // EFI_MEMORY_WB ==> MAIR_ATTR_NORMAL_MEMORY_WRITE_BACK
        reg::set_mair(0x44 << 8 | 0xBB << 16 | 0xFF << 24);

        // Set TTBR0
        reg::set_ttbr0(base.into());

        if !reg::is_mmu_enabled() {
            reg::set_alignment_check(false);
            reg::set_stack_alignment_check(true);
            reg::enable_instruction_cache();
            reg::enable_data_cache();

            reg::enable_mmu();
        }

        Ok(())
    }
}
