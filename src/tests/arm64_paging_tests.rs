use alloc::boxed::Box;

use crate::{
    page_table::{
        arm64::structs::{PageLevel, VirtualAddress, FRAME_SIZE_4KB},
        EFI_MEMORY_RO, EFI_MEMORY_XP,
    },
    page_table_error::{PtError, PtResult},
    page_table_factory::{PageTableFactory, PagingType},
    tests::arm64_test_page_allocator::TestPageAllocator,
};

// Invoke these test suite as cargo test --features "no-reg-rw" . This feature
// will skip writing to CR3 register.

fn find_num_entries(start_offset: u64, end_offset: u64, num_parent_level_entries: u64) -> u64 {
    let mut num_entries = 0;
    if num_parent_level_entries > 1 {
        // entries spanning multiple pages
        num_entries += 512 - start_offset; // number of upper entries in first page
        num_entries += (num_parent_level_entries - 2) * 512; // number of entries in between pages
        num_entries += end_offset + 1; // number of lower entries in the last page
    } else {
        // entries do not span multiple pages(end_offset is guaranteed to be higher than start offset)
        num_entries = end_offset - start_offset + 1; // number of entries in the page
    }

    num_entries
}

fn num_page_tables_required(address: u64, size: u64, paging_type: PagingType) -> PtResult<u64> {
    let address = VirtualAddress::new(address);
    if size == 0 || !address.is_4kb_aligned() {
        return Err(PtError::UnalignedAddress);
    }

    // Check the memory range is aligned
    if !(address + size).is_4kb_aligned() {
        return Err(PtError::UnalignedAddress);
    }

    let start_va = address;
    let end_va = address + size - 1;

    // For the given paging type identify the highest and lowest page levels.
    // This is used during page building to stop the recursion.
    let (highest_page_level, lowest_page_level) = match paging_type {
        PagingType::AArch64PageTable4KB => (PageLevel::Lvl0, PageLevel::Lvl3),
        _ => return Err(PtError::InvalidParameter),
    };
    // println!("address: {:x} size: {:x} start: {:x} end: {:x}", address, size, start, end);

    // The key to calculate the number of tables required for the current level
    // dependents on the number of entries in the parent level. Also, the number
    // of entries in the current level depends on the number of tables in the
    // current level and the current offset(done by `find_num_entries()`).
    let mut num_entries = 0;
    let mut num_tables = 1; // top level table
    let mut total_num_tables = 0;
    for level in ((lowest_page_level as u64)..=(highest_page_level as u64)).rev() {
        let start_offset = start_va.get_index(level.into());
        let end_offset = end_va.get_index(level.into());

        num_entries = find_num_entries(start_offset, end_offset, num_entries);
        // println!("{} num_entries: {}", level, num_entries);
        // println!("{} num_tables: {}", level, num_tables);
        total_num_tables += num_tables;
        num_tables = num_entries;
    }

    // println!("total_num_tables: {}", total_num_tables);

    Ok(total_num_tables)
}

#[test]
fn test_find_num_page_tables() {
    let max_pages: u64 = 10;

    let page_allocator = Box::new(TestPageAllocator::new(max_pages, PagingType::AArch64PageTable4KB));

    let pt = PageTableFactory::init_with_page_type(page_allocator, PagingType::AArch64PageTable4KB);

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
        // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let page_allocator_boxed = Box::new(page_allocator.clone());

        let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = EFI_MEMORY_RO;
        let res = pt.map_memory_region(address, size, attributes);
        // println!("pages allocated: {}", page_allocator.pages_allocated());
        assert!(res.is_ok());

        assert_eq!(page_allocator.pages_allocated(), num_pages);

        page_allocator.validate_pages(address, size, attributes);
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
            let res = pt.map_memory_region(address, size, attributes);
            if res.is_err() {
                println!("addressW: {:x} size: {:x}", address, size);
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
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

        let page_allocator = Box::new(TestPageAllocator::new(max_pages, paging_type));

        let pt = PageTableFactory::init_with_page_type(page_allocator, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = EFI_MEMORY_RO;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
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

        let page_allocator = Box::new(TestPageAllocator::new(max_pages, paging_type));

        let pt = PageTableFactory::init_with_page_type(page_allocator, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = EFI_MEMORY_RO;
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
        // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let page_allocator_boxed = Box::new(page_allocator.clone());

        let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = EFI_MEMORY_RO;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
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

        let page_allocator = Box::new(TestPageAllocator::new(max_pages, paging_type));

        let pt = PageTableFactory::init_with_page_type(page_allocator, paging_type);

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

        let page_allocator = Box::new(TestPageAllocator::new(max_pages, paging_type));

        let pt = PageTableFactory::init_with_page_type(page_allocator, paging_type);

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
        // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let page_allocator_boxed = Box::new(page_allocator.clone());

        let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = EFI_MEMORY_RO;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
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

    let page_allocator = Box::new(TestPageAllocator::new(max_pages, PagingType::AArch64PageTable4KB));

    let pt = PageTableFactory::init_with_page_type(page_allocator, PagingType::AArch64PageTable4KB);

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

    let page_allocator = Box::new(TestPageAllocator::new(max_pages, PagingType::AArch64PageTable4KB));

    let pt = PageTableFactory::init_with_page_type(page_allocator, PagingType::AArch64PageTable4KB);

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
        // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let page_allocator_boxed = Box::new(page_allocator.clone());

        let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = EFI_MEMORY_RO;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let attributes = EFI_MEMORY_XP;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = EFI_MEMORY_XP;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let attributes = EFI_MEMORY_XP;
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
            // println!("num pages: {} address: {:x} size: {:x}", num_pages, address, size);

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let page_allocator_boxed = Box::new(page_allocator.clone());

            let pt = PageTableFactory::init_with_page_type(page_allocator_boxed, paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = EFI_MEMORY_RO;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = EFI_MEMORY_XP;
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

        let page_allocator = Box::new(TestPageAllocator::new(max_pages, paging_type));

        let pt = PageTableFactory::init_with_page_type(page_allocator, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = EFI_MEMORY_XP;
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

        let page_allocator = Box::new(TestPageAllocator::new(max_pages, paging_type));

        let pt = PageTableFactory::init_with_page_type(page_allocator, paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = EFI_MEMORY_XP;
        let res = pt.remap_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}
