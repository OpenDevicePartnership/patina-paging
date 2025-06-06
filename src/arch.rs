use crate::{
    MemoryAttributes, PagingType, PtResult,
    paging::PageTableState,
    structs::{PageLevel, PhysicalAddress, VirtualAddress},
};

pub(crate) trait PageTableHal {
    type PTE: PageTableEntry;
    const DEFAULT_ATTRIBUTES: MemoryAttributes;

    unsafe fn zero_page(base: VirtualAddress);
    fn paging_type_supported(paging_type: PagingType) -> PtResult<()>;
    fn get_zero_va(paging_type: PagingType) -> PtResult<VirtualAddress>;
    fn invalidate_tlb(va: VirtualAddress);
    fn get_max_va(page_type: PagingType) -> PtResult<VirtualAddress>;
    fn is_table_active(base: u64) -> bool;
    unsafe fn install_page_table(base: u64) -> PtResult<()>;
    fn level_supports_pa_entry(level: PageLevel) -> bool;
}

pub(crate) trait PageTableEntry {
    fn new(
        page_base: PhysicalAddress,
        index: u64,
        level: PageLevel,
        paging_type: PagingType,
        start_va: VirtualAddress,
        state: PageTableState,
    ) -> PtResult<Self>
    where
        Self: Sized;

    fn update_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress, leaf_entry: bool) -> PtResult<()>;
    fn present(&self) -> bool;
    fn set_present(&mut self, value: bool);
    fn get_address(&self) -> PhysicalAddress;
    fn get_attributes(&self) -> MemoryAttributes;
    fn dump_entry_header();
    fn dump_entry(&self) -> PtResult<()>;
    fn points_to_pa(&self) -> bool;
    fn get_level(&self) -> PageLevel;
    fn entry_ptr_address(&self) -> u64;
}
