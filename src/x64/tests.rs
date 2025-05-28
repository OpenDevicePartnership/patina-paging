use crate::{
    MemoryAttributes, PageTable, PagingType, PtError,
    structs::{PAGE_SIZE, SELF_MAP_INDEX, ZERO_VA_INDEX},
    tests::test_page_allocator::TestPageAllocator,
    x64::{
        X64PageTable,
        structs::{CR3_PAGE_BASE_ADDRESS_MASK, PageTableEntryX64},
    },
};

#[test]
fn test_map_memory_address_range_overflow() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        // VA range overflows
        TestConfig { paging_type: PagingType::Paging4Level, address: 0xFFFF_FEFF_FFFF_F000, size: 0x3000 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0xFFFD_FFFF_FFFF_F000, size: 0x3000 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = X64PageTable::new(page_allocator, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

#[test]
fn test_self_map() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
    }

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1000 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1000 },
    ];

    for test_config in test_configs {
        let TestConfig { address, paging_type } = test_config;

        let page_allocator = TestPageAllocator::new(0x1000, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        // Create some pages before the install, so VA = PA for accessing
        for i in 0..10 {
            let test_address = address + i * PAGE_SIZE;
            let test_size = PAGE_SIZE;
            let test_attributes = match i % 3 {
                0 => MemoryAttributes::ReadOnly,
                1 => MemoryAttributes::empty(),
                _ => MemoryAttributes::ExecuteProtect,
            };

            let res = pt.map_memory_region(test_address, test_size, test_attributes);
            assert!(res.is_ok());

            let res = pt.query_memory_region(test_address, test_size);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), test_attributes);
        }

        let res = pt.install_page_table();
        assert!(res.is_ok());

        let root = pt.into_page_table_root();

        // now we should see the zero VA and the self map entries in the base page table
        let zero_va_top_level = root + ZERO_VA_INDEX * size_of::<PageTableEntryX64>() as u64;
        assert!(unsafe { *(zero_va_top_level as *const u64) != 0 });

        let zero_va_pdp_level = unsafe { *(zero_va_top_level as *const u64) & !0xFFF };
        assert!(unsafe { *(zero_va_pdp_level as *const u64) != 0 });

        let zero_va_pd_level = unsafe { *(zero_va_pdp_level as *const u64) & !0xFFF };
        assert!(unsafe { *(zero_va_pd_level as *const u64) != 0 });

        let zero_va_pt_level = unsafe { *(zero_va_pd_level as *const u64) & !0xFFF };
        assert!(unsafe { *(zero_va_pt_level as *const u64) != 0 });

        match paging_type {
            PagingType::Paging4Level => {
                // 4 level paging ends here, we expect the zero VA to be unmapped
                let zero_va_pa = unsafe { *(zero_va_pt_level as *const u64) & !0xFFF };
                assert!(zero_va_pa == 0);
            }
            PagingType::Paging5Level => {
                // 5 level paging has another level to it, so names above aren't correct
                let zero_va_real_pt_level = unsafe { *(zero_va_pt_level as *const u64) & !0xFFF };
                assert!(unsafe { *(zero_va_pt_level as *const u64) != 0 });

                let zero_va_pa_level = unsafe { *(zero_va_real_pt_level as *const u64) & !0xFFF };
                assert!(zero_va_pa_level == 0);
            }
        }

        let self_map_top_level = root + SELF_MAP_INDEX * size_of::<PageTableEntryX64>() as u64;
        assert_eq!(unsafe { *(self_map_top_level as *const u64) } & CR3_PAGE_BASE_ADDRESS_MASK, root);
    }
}
