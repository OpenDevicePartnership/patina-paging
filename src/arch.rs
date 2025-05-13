use crate::{
    structs::{PageLevel, PhysicalAddress, VirtualAddress},
    MemoryAttributes, PagingType, PtResult,
};
use alloc::string::String;

pub trait PageTableArch {
    type PTE: PageTableEntry;

    unsafe fn zero_page(base: VirtualAddress);
    fn paging_type_supported(paging_type: PagingType) -> PtResult<()>;
    fn get_zero_va(paging_type: PagingType) -> PtResult<VirtualAddress>;
    fn invalidate_tlb(va: Option<VirtualAddress>);
    fn get_max_va(page_type: PagingType) -> PtResult<VirtualAddress>;
    fn is_table_active(base: u64) -> bool;
    unsafe fn install_page_table(base: u64) -> PtResult<()>;
}

pub trait PageTableEntry {
    fn new(
        page_base: PhysicalAddress,
        index: u64,
        level: PageLevel,
        paging_type: PagingType,
        start_va: VirtualAddress,
        installed_and_self_mapped: bool,
    ) -> Self;

    fn update_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress, leaf_entry: bool) -> PtResult<()>;
    fn present(&self) -> bool;
    fn set_present(&mut self, value: bool);
    fn get_canonical_page_table_base(&self) -> PhysicalAddress;
    fn get_attributes(&self) -> MemoryAttributes;
    fn dump_entry(&self) -> String;
    fn points_to_pa(&self) -> bool;
    fn get_level(&self) -> PageLevel;
    fn raw_address(&self) -> u64;
    fn supports_pa_entry(&self) -> bool;
}
