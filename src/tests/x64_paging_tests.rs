use crate::{
    tests::x64_test_page_allocator::TestPageAllocator,
    x64::{
        paging::{num_page_tables_required, X64PageTable},
        structs::*,
    },
    MemoryAttributes, PageTable, PagingType, PtError,
};
use log::{Level, LevelFilter, Metadata, Record};

// Sample logger for log crate to dump stuff in tests
struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{}", record.args());
        }
    }

    fn flush(&self) {}
}
static LOGGER: SimpleLogger = SimpleLogger;

fn set_logger() {
    let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info));
}

#[test]
fn test_find_num_page_tables() {
    // Mapping one page of physical address require 4 page tables(PML4/PDP/PD/PT)
    let address = 0x0;
    let size = FRAME_SIZE_4KB; // 4k
    let res = num_page_tables_required(address, size, PagingType::Paging4Level);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 511 pages of physical address require 4 page tables(PML4/PDP/PD/PT)
    let address = FRAME_SIZE_4KB;
    let size = 511 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::Paging4Level);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 512 pages of physical address require 3 page tables because of 2mb pages.(PML4/PDP/PD)
    let address = 0x0;
    let size = 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::Paging4Level);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 3);

    // Mapping 513 pages of physical address require 4 page tables because it will be 1 2mb mapping and 1 4kb.
    // (PML5(1)/PML4(1)/PDPE(1)/PDP(1)/PT(1))
    let address = 0x0;
    let size = 513 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::Paging4Level);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 1gb of physical address require 2 page tables because of 1Gb pages.(PML4/PDP)
    let address = 0x0;
    let size = 512 * 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::Paging4Level);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 2);

    // Mapping 1 1GbPage + 1 2mb page + 1 4kb page require 4 page tables.(PML4/PDP/PD/PT)
    let address = 0x0;
    let size = (512 * 512 * FRAME_SIZE_4KB) + (512 * FRAME_SIZE_4KB) + FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::Paging4Level);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 2mb starting at 2mb/2 should take 5 pages. (PML4/PDP/PD(1)/PT(2))
    let address = 256 * FRAME_SIZE_4KB;
    let size = 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::Paging4Level);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 5);

    // Mapping 10Gb starting at 4kb should take 6 pages. (PML4/PDP/PD(2)/PT(2))
    let address = FRAME_SIZE_4KB;
    let size = 10 * 512 * 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::Paging4Level);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 6);
}

// Memory map tests

#[test]
fn test_map_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0, size: 0x400000 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0, size: 0x400000 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
        let res = pt.map_memory_region(address, size, attributes);

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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0, size: FRAME_SIZE_4KB },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0, size: FRAME_SIZE_4KB },
    ];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            log::info!("allocated: {} expected: {}", page_allocator.pages_allocated(), num_pages);
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

    let test_configs = [
        TestConfig {
            paging_type: PagingType::Paging4Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB,
        },
        TestConfig {
            paging_type: PagingType::Paging5Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB,
        },
    ];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
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

    let test_configs = [
        TestConfig {
            paging_type: PagingType::Paging4Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB << 1,
        },
        TestConfig {
            paging_type: PagingType::Paging5Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB << 1,
        },
    ];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1, size: 200 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1, size: 200 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
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
        TestConfig { paging_type: PagingType::Paging4Level, address: 0xffff_ffff_ffff_f000, size: 0x2000 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0xffff_ffff_ffff_f000, size: 0x2000 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1000, size: 0 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1000, size: 0 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1000, size: FRAME_SIZE_4KB * 512 * 512 * 10 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1000, size: FRAME_SIZE_4KB * 512 * 512 * 10 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0, size: FRAME_SIZE_4KB },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0, size: FRAME_SIZE_4KB },
    ];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
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

    let test_configs = [
        TestConfig {
            paging_type: PagingType::Paging4Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB,
        },
        TestConfig {
            paging_type: PagingType::Paging5Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB,
        },
    ];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, address_increment } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
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

    let test_configs = [
        TestConfig {
            paging_type: PagingType::Paging4Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB << 1,
        },
        TestConfig {
            paging_type: PagingType::Paging5Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB << 1,
        },
    ];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, address_increment } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1, size: 200 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1, size: 200 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1000, size: 0 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1000, size: 0 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1000, size: FRAME_SIZE_4KB * 512 * 512 * 10 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1000, size: FRAME_SIZE_4KB * 512 * 512 * 10 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let res = pt.query_memory_region(address, size);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), attributes);
    }
}

#[test]
fn test_query_memory_address_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1000, size: FRAME_SIZE_4KB },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1000, size: FRAME_SIZE_4KB },
    ];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;
        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), attributes);
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0, size: FRAME_SIZE_4KB, step: FRAME_SIZE_4KB },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0, size: FRAME_SIZE_4KB, step: FRAME_SIZE_4KB },
    ];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, step } = test_config;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), attributes);
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

    let test_configs = [
        TestConfig {
            paging_type: PagingType::Paging4Level,
            address: 0,
            size: FRAME_SIZE_4KB << 1,
            step: FRAME_SIZE_4KB,
        },
        TestConfig {
            paging_type: PagingType::Paging5Level,
            address: 0,
            size: FRAME_SIZE_4KB << 1,
            step: FRAME_SIZE_4KB,
        },
    ];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, step } = test_config;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), attributes);
            address += step;
        }
    }
}

#[test]
fn test_query_memory_address_unaligned() {
    let max_pages: u64 = 10;

    let page_allocator = TestPageAllocator::new(max_pages, PagingType::Paging4Level);

    let pt = X64PageTable::new(page_allocator.clone(), PagingType::Paging4Level);

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

    let page_allocator = TestPageAllocator::new(max_pages, PagingType::Paging4Level);

    let pt = X64PageTable::new(page_allocator.clone(), PagingType::Paging4Level);

    assert!(pt.is_ok());
    let pt = pt.unwrap();

    let address = 0x1000;
    let size = 0;
    let res = pt.query_memory_region(address, size);
    assert!(res.is_err());
    assert_eq!(res, Err(PtError::InvalidMemoryRange));
}

// Memory remap tests
#[test]
fn test_remap_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1000, size: FRAME_SIZE_4KB * 512 * 512 * 10 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1000, size: FRAME_SIZE_4KB * 512 * 512 * 10 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let attributes = MemoryAttributes::ExecuteProtect;
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0, size: FRAME_SIZE_4KB },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0, size: FRAME_SIZE_4KB },
    ];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = MemoryAttributes::ExecuteProtect;
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

    let test_configs = [
        TestConfig {
            paging_type: PagingType::Paging4Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB,
        },
        TestConfig {
            paging_type: PagingType::Paging5Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB,
        },
    ];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let attributes = MemoryAttributes::ExecuteProtect;
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

    let test_configs = [
        TestConfig {
            paging_type: PagingType::Paging4Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB << 1,
        },
        TestConfig {
            paging_type: PagingType::Paging5Level,
            address: 0,
            address_increment: FRAME_SIZE_4KB,
            size: FRAME_SIZE_4KB << 1,
        },
    ];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = MemoryAttributes::ExecuteProtect;
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1, size: 200 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1, size: 200 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ExecuteProtect;
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

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1000, size: 0 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1000, size: 0 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ExecuteProtect;
        let res = pt.remap_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

#[test]
fn test_from_existing_page_table() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        TestConfig { paging_type: PagingType::Paging4Level, address: 0x1000, size: FRAME_SIZE_4KB * 512 * 512 * 10 },
        TestConfig { paging_type: PagingType::Paging5Level, address: 0x1000, size: FRAME_SIZE_4KB * 512 * 512 * 10 },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        // Create a new page table from the existing one
        let new_pt =
            unsafe { X64PageTable::from_existing(pt.into_page_table_root(), page_allocator.clone(), paging_type) };
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

    let test_configs = [TestConfig { paging_type: PagingType::Paging4Level, address: 0, size: 0x8000 }];

    set_logger();

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = X64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());

        pt.dump_page_tables(address, size);
    }
}

#[test]
fn test_large_page_splitting() {
    struct TestRange {
        address: u64,
        size: u64,
    }

    impl TestRange {
        fn as_range(&self) -> core::ops::Range<u64> {
            self.address..self.address + self.size
        }
    }

    struct TestConfig {
        paging_type: PagingType,
        mapped_range: TestRange,
        split_range: TestRange,
        page_increase: u64,
    }

    let test_configs = [
        TestConfig {
            paging_type: PagingType::Paging4Level,
            mapped_range: TestRange { address: 0, size: 0x200000 },
            split_range: TestRange { address: 0, size: 0x1000 },
            page_increase: 1, // 1 2MB page split into 4KB pages, adds 1 PT.
        },
        TestConfig {
            paging_type: PagingType::Paging5Level,
            mapped_range: TestRange { address: 0, size: 0x200000 },
            split_range: TestRange { address: 0, size: 0x1000 },
            page_increase: 1, // 1 2MB page split into 4KB pages, adds 1 PT.
        },
        TestConfig {
            paging_type: PagingType::Paging4Level,
            mapped_range: TestRange { address: 0, size: 0x600000 },
            split_range: TestRange { address: 0x100000, size: 0x400000 },
            page_increase: 2, // 3 2MB pages split into 1 2MB with 4KB on either side, adds 2 PT.
        },
        TestConfig {
            paging_type: PagingType::Paging4Level,
            mapped_range: TestRange { address: 0, size: 0x40000000 },
            split_range: TestRange { address: 0, size: 0x1000 },
            page_increase: 2, // 1 1GB page split into 4KB + 2MB pages, adds 1PD + 1 PT.
        },
        TestConfig {
            paging_type: PagingType::Paging4Level,
            mapped_range: TestRange { address: 0, size: 0x40000000 },
            split_range: TestRange { address: 0, size: 0x200000 },
            page_increase: 1, // 1 1GB page split into 2MB pages, adds 1PD.
        },
        TestConfig {
            paging_type: PagingType::Paging4Level,
            mapped_range: TestRange { address: 0, size: 0x40000000 },
            split_range: TestRange { address: 0x1FF000, size: 0x2000 },
            page_increase: 3, // 1 1GB page split into 4KB + 2MB pages along 2 2MB pages, adds 1PD + 2 PT.
        },
    ];

    enum TestAction {
        Unmap,
        Remap,
    }

    let orig_attributes = MemoryAttributes::empty();
    let remap_attributes = MemoryAttributes::ExecuteProtect;

    // Test the splitting when remapping.
    for test_config in test_configs {
        let TestConfig { paging_type, mapped_range, split_range, page_increase } = test_config;
        for action in [TestAction::Unmap, TestAction::Remap] {
            let num_pages = num_page_tables_required(mapped_range.address, mapped_range.size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages + page_increase, paging_type);
            let pt = X64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let res = pt.map_memory_region(mapped_range.address, mapped_range.size, orig_attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = match action {
                TestAction::Unmap => pt.unmap_memory_region(split_range.address, split_range.size),
                TestAction::Remap => pt.remap_memory_region(split_range.address, split_range.size, remap_attributes),
            };
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages + page_increase);

            for page in mapped_range.as_range().step_by(0x1000) {
                let res = pt.query_memory_region(page, FRAME_SIZE_4KB);
                match action {
                    TestAction::Unmap => {
                        if split_range.as_range().contains(&page) {
                            assert!(res.is_err())
                        } else {
                            assert!(res.is_ok())
                        }
                    }
                    TestAction::Remap => {
                        let check_attributes =
                            if split_range.as_range().contains(&page) { remap_attributes } else { orig_attributes };
                        assert!(res.is_ok());
                        assert_eq!(res.unwrap(), check_attributes);
                    }
                }
            }
        }
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
            let test_address = address + i * FRAME_SIZE_4KB;
            let test_size = FRAME_SIZE_4KB;
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
        let zero_va_top_level = root + ZERO_VA_INDEX * size_of::<PageTableEntry>() as u64;
        assert!(unsafe { *(zero_va_top_level as *const u64) != 0 });

        let self_map_top_level = root + SELF_MAP_INDEX * size_of::<PageTableEntry>() as u64;
        assert_eq!(unsafe { *(self_map_top_level as *const u64) } & CR3_PAGE_BASE_ADDRESS_MASK, root);
    }
}

#[test]
fn test_install_page_table() {
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
            let test_address = address + i * FRAME_SIZE_4KB;
            let test_size = FRAME_SIZE_4KB;
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

        // Try mapping some new pages after the install
        for i in 10..20 {
            let test_address = address + i * FRAME_SIZE_4KB;
            let test_size = FRAME_SIZE_4KB;
            let test_attributes = match i % 3 {
                0 => MemoryAttributes::ReadOnly,
                1 => MemoryAttributes::empty(),
                _ => MemoryAttributes::ExecuteProtect,
            };

            let res = pt.map_memory_region(test_address, test_size, test_attributes);
            if res.is_err() {
                log::error!("Page fault occurred while mapping address: {:#x}", test_address);
                continue;
            }

            // Confirm querying the new pages show they are mapped
            let res = pt.query_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while querying address: {:#x}", test_address);
                continue;
            }
            assert_eq!(res.unwrap(), test_attributes);
        }

        // Now try remapping some of the originally mapped pages
        for i in 0..2 {
            let test_address = address + i * FRAME_SIZE_4KB;
            let test_size = FRAME_SIZE_4KB;
            let test_attributes = match i % 3 {
                0 => MemoryAttributes::ReadOnly,
                1 => MemoryAttributes::empty(),
                _ => MemoryAttributes::ExecuteProtect,
            };

            let res = pt.remap_memory_region(test_address, test_size, test_attributes);
            if res.is_err() {
                log::error!("Page fault occurred while remapping address: {:#x}", test_address);
                continue;
            }

            // Confirm querying the remapped pages show they are remapped
            let res = pt.query_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while querying address: {:#x}", test_address);
                continue;
            }
            assert_eq!(res.unwrap(), test_attributes);
        }

        // Now try unmapping some of the original pages
        for i in 2..4 {
            let test_address = address + i * FRAME_SIZE_4KB;
            let test_size = FRAME_SIZE_4KB;

            let res = pt.unmap_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while unmapping address: {:#x}", test_address);
                continue;
            }

            // Confirm querying the unmapped pages show they are unmapped
            let res = pt.query_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while querying address: {:#x}", test_address);
                continue;
            }
        }
    }
}
