use alloc::boxed::Box;

#[cfg(any(target_arch = "aarch64", test))]
use crate::page_table::arm64::paging::AArch64PageTable;
#[cfg(any(target_arch = "x86_64", test))]
use crate::page_table::x64::paging::X64PageTable;

use crate::{page_allocator::PageAllocator, page_table::PageTable, page_table_error::PtResult};

// Initialization of a PageTable trait object (i.e., `dyn PageTable`) requires
// that the trait does not have any associated functions like `init()`, meaning
// functions without `&self` or `&mut self` parameters. This restriction exists
// only when trying to create a trait object (for polymorphism behavior). An
// alternative is to move the `init()` method outside of the trait and create a
// page table factory as shown below. For more info refer:
// <https://doc.rust-lang.org/reference/items/traits.html#object-safety>
pub struct PageTableFactory;

impl PageTableFactory {
    /// Initialize the page table instance by providing the page allocator trait
    /// object provided by the core. This object will be used to initialize the
    /// root page table and return the page table instance.
    ///
    /// ## Arguments
    /// * `page_allocator` - The page allocator trait object provided by the
    ///   core.
    ///
    /// ## Returns
    /// * `PageTable` - The page table instance.
    ///
    /// ## Errors
    pub fn init(page_allocator: Box<dyn PageAllocator>) -> PtResult<Box<dyn PageTable>> {
        #[cfg(target_arch = "x86_64")]
        {
            Ok(Box::new(X64PageTable::new(page_allocator, PagingType::Paging4KB4Level)?))
        }
        #[cfg(target_arch = "aarch64")]
        {
            Ok(Box::new(AArch64PageTable::new(page_allocator, PagingType::AArch64PageTable4KB)?))
        }
    }

    /// This initialize method is for testing purpose and it accepts the paging
    /// type as an argument.
    #[cfg(test)]
    pub fn init_with_page_type(
        page_allocator: Box<dyn PageAllocator>,
        page_table_type: PagingType,
    ) -> PtResult<Box<dyn PageTable>> {
        match page_table_type {
            PagingType::Paging4KB5Level => {
                Ok(Box::new(X64PageTable::new(page_allocator, PagingType::Paging4KB5Level)?))
            }
            PagingType::Paging4KB4Level => {
                Ok(Box::new(X64PageTable::new(page_allocator, PagingType::Paging4KB4Level)?))
            }
            PagingType::AArch64PageTable4KB => {
                Ok(Box::new(AArch64PageTable::new(page_allocator, PagingType::AArch64PageTable4KB)?))
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PagingType {
    Paging4KB5Level,
    Paging4KB4Level,
    AArch64PageTable4KB,
}
