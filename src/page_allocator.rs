use crate::PtResult;

/// PageAllocator trait facilitates `allocate_page()` method for allocating new
/// pages
pub trait PageAllocator {
    /// Allocate aligned pages from physical memory.
    ///
    /// ## Arguments
    /// * `align` - on x64 this will be 4KB page alignment.
    /// * `size` - on x64 this will be 4KB page size.
    /// * `is_root` - on x64 this will be true if the page is root page. This can be used to allow the system to
    ///   make certain adjustments required for the root page on some systems
    ///
    /// ## Returns
    /// * `PtResult<u64>` - Physical address of the allocated page.
    fn allocate_page(&mut self, align: u64, size: u64, is_root: bool) -> PtResult<u64>;
}
