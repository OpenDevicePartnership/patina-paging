use crate::page_table_error::PtResult;

/// PageAllocator trait facilitates `allocate_page()` method for allocating new
/// pages
pub trait PageAllocator {
    /// Allocate aligned pages from physical memory.
    ///
    /// ## Arguments
    /// * `align` - on x64 this will be 4KB page alignment.
    /// * `size` - on x64 this will be 4KB page size.
    ///
    /// ## Returns
    /// * `PtResult<u64>` - Physcial address of the allocated page.
    fn allocate_page(&mut self, align: u64, size: u64) -> PtResult<u64>;
}
