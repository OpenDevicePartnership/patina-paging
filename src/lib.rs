#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
extern crate alloc;
pub mod page_allocator;
pub mod page_table;
pub mod page_table_error;
pub mod page_table_factory;

#[cfg(test)]
mod tests;
