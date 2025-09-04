//! Unit tests for AArch64 page table and memory management functionality.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use crate::{
    MemoryAttributes, PageTable, PagingType, PtError,
    aarch64::{
        AArch64PageTable,
        structs::{FOUR_LEVEL_LEVEL4_SELF_MAP_BASE, PageTableEntryAArch64, ZERO_VA_4_LEVEL},
    },
    structs::{PAGE_SIZE, SELF_MAP_INDEX, ZERO_VA_INDEX},
    tests::test_page_allocator::TestPageAllocator,
};

#[test]
fn test_map_memory_address_range_overflow_aarch64() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        // VA range overflows
        TestConfig {
            paging_type: PagingType::Paging4Level,
            address: 0x0000_FEFF_FFFF_F000,
            size: 0x0000_FEFF_FFFF_F000,
        },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = AArch64PageTable::new(page_allocator, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

#[test]
fn test_self_map() {
    struct TestConfig {
        paging_type: PagingType,
    }

    let test_configs = [TestConfig { paging_type: PagingType::Paging4Level }];

    for test_config in test_configs {
        let TestConfig { paging_type } = test_config;

        let page_allocator = TestPageAllocator::new(0x1000, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let pt = pt.unwrap();

        // ensure the self map is present
        let res = pt.query_memory_region(FOUR_LEVEL_LEVEL4_SELF_MAP_BASE, PAGE_SIZE);
        assert!(res.is_ok());

        // we can't query the zero VA because in new() it is not mapped on purpose, so we just check we mapped
        // down to the PTE level
        let res = pt.query_memory_region(ZERO_VA_4_LEVEL, PAGE_SIZE);
        assert!(res.is_err());

        let root = pt.into_page_table_root();

        // now we should see the zero VA and the self map entries in the base page table
        let zero_va_top_level = root + ZERO_VA_INDEX * size_of::<PageTableEntryAArch64>() as u64;
        assert!(unsafe { *(zero_va_top_level as *const u64) != 0 });

        let zero_va_pdp_level = unsafe { *(zero_va_top_level as *const u64) & !0xFFF };
        assert!(unsafe { *(zero_va_pdp_level as *const u64) != 0 });

        let zero_va_pd_level = unsafe { *(zero_va_pdp_level as *const u64) & !0xFFF };
        assert!(unsafe { *(zero_va_pd_level as *const u64) != 0 });

        let zero_va_pt_level = unsafe { *(zero_va_pd_level as *const u64) & !0xFFF };
        assert!(unsafe { *(zero_va_pt_level as *const u64) != 0 });

        let zero_va_pa = unsafe { *(zero_va_pt_level as *const u64) & !0xFFF };
        assert!(zero_va_pa == 0);

        let self_map_top_level = root + SELF_MAP_INDEX * size_of::<PageTableEntryAArch64>() as u64;
        assert_eq!((unsafe { *(self_map_top_level as *const u64) } & !0xFFF), root);
    }
}
