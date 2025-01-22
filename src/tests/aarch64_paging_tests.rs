use crate::{
    aarch64::{
        paging::{num_page_tables_required, AArch64PageTable},
        structs::{FRAME_SIZE_4KB, MAX_VA},
    },
    tests::aarch64_test_page_allocator::TestPageAllocator,
    MemoryAttributes, PageTable, PagingType, PtError,
};

#[test]
fn test_find_num_page_tables() {
    let max_pages: u64 = 10;

    let page_allocator = TestPageAllocator::new(max_pages, PagingType::AArch64PageTable4KB);

    let pt = AArch64PageTable::new(page_allocator.clone(), PagingType::AArch64PageTable4KB);

    assert!(pt.is_ok());

    // Mapping one page of physical address require 5 page tables(PML5/PML4/PDPE/PDP/PT)
    let address = 0x0;
    let size = FRAME_SIZE_4KB; // 4k
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping one page of physical address require 5 page tables(PML5/PML4/PDPE/PDP/PT)
    let address = FRAME_SIZE_4KB;
    let size = FRAME_SIZE_4KB << 1;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 512 pages of physical address require 5 page tables(PML5/PML4/PDPE/PDP/PT)
    let address = 0x0;
    let size = 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 513 pages of physical address require 6 page tables(PML5(1)/PML4(1)/PDPE(1)/PDP(1)/PT(2))
    let address = 0x0;
    let size = 512 * FRAME_SIZE_4KB + FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 5);

    // Mapping 512 + 512 pages of physical address require 6 page tables(PML5(1)/PML4(1)/PDPE(1)/PDP(1)/PT(2))
    let address = 0x0;
    let size = 512 * FRAME_SIZE_4KB + 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 5);
}

// Memory map tests

#[test]
fn test_map_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: 0x400000 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());

        assert_eq!(page_allocator.pages_allocated(), num_pages);

        page_allocator.validate_pages(address, size, attributes);
    }
}

#[test]
fn test_map_memory_address_not_so_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: 0x400000 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::Uncacheable;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());

        assert_eq!(page_allocator.pages_allocated(), num_pages);

        // This is expected behavior as the uncacheable attribute is does not support execute per the MMU implementation
        page_allocator.validate_pages(address, size, attributes | MemoryAttributes::ExecuteProtect);
    }
}

#[test]
fn test_map_memory_address_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: FRAME_SIZE_4KB }];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            if res.is_err() {
                log::info!("addressW: {:x} size: {:x}", address, size);
            }
            assert!(res.is_ok());

            assert_eq!(page_allocator.pages_allocated(), num_pages);

            page_allocator.validate_pages(address, size, attributes);

            size <<= 1;
        }
    }
}

#[test]
fn test_map_memory_address_single_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,

        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            assert_eq!(page_allocator.pages_allocated(), num_pages);
            page_allocator.validate_pages(address, size, attributes);

            address += address_increment;
        }
    }
}

#[test]
fn test_map_memory_address_multiple_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB << 1,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            assert_eq!(page_allocator.pages_allocated(), num_pages);
            page_allocator.validate_pages(address, size, attributes);

            address += address_increment;
        }
    }
}

#[test]
fn test_map_memory_address_unaligned() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1, size: 200 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}

#[test]
fn test_map_memory_address_range_overflow() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        // VA range overflows
        TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: MAX_VA, size: MAX_VA },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

#[test]
fn test_map_memory_address_invalid_range() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        // VA above the valid address range
        TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: MAX_VA + 1, size: FRAME_SIZE_4KB },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

#[test]
fn test_map_memory_address_zero_size() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1, size: 0 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}

// Memory unmap tests

#[test]
fn test_unmap_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0x1000,
        size: FRAME_SIZE_4KB * 512 * 512 * 10,
    }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_ok());
    }
}

#[test]
fn test_unmap_memory_address_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: FRAME_SIZE_4KB }];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.unmap_memory_region(address, size);
            assert!(res.is_ok());
            size <<= 1;
        }
    }
}

#[test]
fn test_unmap_memory_address_single_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,

        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, address_increment } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let res = pt.unmap_memory_region(address, size);
            assert!(res.is_ok());
            address += address_increment;
        }
    }
}

#[test]
fn test_unmap_memory_address_multiple_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB << 1,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, address_increment } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.unmap_memory_region(address, size);
            assert!(res.is_ok());
            address += address_increment;
        }
    }
}

#[test]
fn test_unmap_memory_address_unaligned() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1, size: 200 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}

#[test]
fn test_unmap_memory_address_zero_size() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1, size: 0 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}

// Memory query tests
#[test]
fn test_query_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0x1000,
        size: FRAME_SIZE_4KB * 512 * 512 * 10,
    }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let res = pt.query_memory_region(address, size);
        assert!(res.is_ok());
    }
}

#[test]
fn test_query_memory_address_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs =
        [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1000, size: FRAME_SIZE_4KB }];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;
        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            size <<= 1;
        }
    }
}

#[test]
fn test_query_memory_address_single_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        step: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        size: FRAME_SIZE_4KB,
        step: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, step } = test_config;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            address += step;
        }
    }
}

#[test]
fn test_query_memory_address_multiple_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        step: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        size: FRAME_SIZE_4KB << 1,
        step: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, step } = test_config;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            address += step;
        }
    }
}

#[test]
fn test_query_memory_address_unaligned() {
    let max_pages: u64 = 10;

    let page_allocator = TestPageAllocator::new(max_pages, PagingType::AArch64PageTable4KB);

    let pt = AArch64PageTable::new(page_allocator.clone(), PagingType::AArch64PageTable4KB);

    assert!(pt.is_ok());
    let pt = pt.unwrap();

    let address = 0x1;
    let size = 200;
    let res = pt.query_memory_region(address, size);
    assert!(res.is_err());
    assert_eq!(res, Err(PtError::UnalignedAddress));
}

#[test]
fn test_query_memory_address_zero_size() {
    let max_pages: u64 = 10;

    let page_allocator = TestPageAllocator::new(max_pages, PagingType::AArch64PageTable4KB);

    let pt = AArch64PageTable::new(page_allocator.clone(), PagingType::AArch64PageTable4KB);

    assert!(pt.is_ok());
    let pt = pt.unwrap();

    let address = 0x1;
    let size = 0;
    let res = pt.query_memory_region(address, size);
    assert!(res.is_err());
    assert_eq!(res, Err(PtError::UnalignedAddress));
}

// Memory remap tests
#[test]
fn test_remap_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0x1000,
        size: FRAME_SIZE_4KB * 512 * 512 * 10,
    }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
        let res = pt.remap_memory_region(address, size, attributes);
        assert!(res.is_ok());
    }
}

#[test]
fn test_remap_memory_address_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: FRAME_SIZE_4KB }];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
            let res = pt.remap_memory_region(address, size, attributes);
            assert!(res.is_ok());
            size <<= 1;
        }
    }
}

#[test]
fn test_remap_memory_address_single_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,

        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
            let res = pt.remap_memory_region(address, size, attributes);
            assert!(res.is_ok());
            address += address_increment;
        }
    }
}

#[test]
fn test_remap_memory_address_multiple_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB << 1,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
            let res = pt.remap_memory_region(address, size, attributes);
            assert!(res.is_ok());
            address += address_increment;
        }
    }
}

#[test]
fn test_remap_memory_address_unaligned() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1, size: 200 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
        let res = pt.remap_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}

#[test]
fn test_remap_memory_address_zero_size() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1, size: 0 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
        let res = pt.remap_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}

#[test]
fn test_from_existing_page_table() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0x1000,
        size: FRAME_SIZE_4KB * 512 * 512 * 10,
    }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        // Create a new page table from the existing one
        let new_pt =
            unsafe { AArch64PageTable::from_existing(pt.into_page_table_root(), page_allocator.clone(), paging_type) };
        assert!(new_pt.is_ok());
        let new_pt = new_pt.unwrap();

        // Validate the new page table
        let res = new_pt.query_memory_region(address, size);
        assert!(res.is_ok());
    }
}

#[test]
fn test_dump_page_tables() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: 0x4000 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());

        pt.dump_page_tables(address, size);
    }
}
