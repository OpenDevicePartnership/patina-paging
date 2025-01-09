use core::arch::{asm, global_asm};

global_asm!(include_str!("replace_table_entry.asm"));

// Use efiapi for the consistent calling convention.
extern "efiapi" {
    pub fn replace_live_xlat_entry(entry_ptr: u64, val: u64, addr: u64);
}

pub fn get_phys_addr_bits() -> u64 {
    // read the id_aa64mmfr0_el1 register to get the physical address bits
    // Bits 0..3 of the id_aa64mmfr0_el1 system register encode the size of the
    // physical address space support on this CPU:
    // 0 == 32 bits, 1 == 36 bits, etc etc
    // 7 and up are reserved
    //
    // The value is encoded as 2^(n+1) where n is the number of bits
    // supported. So 0b0000 == 2^32 == 4GB, 0b0001 == 2^36 == 8GB, etc
    let mut pa_bits: u64;

    unsafe {
        asm!(
          "mrs {}, id_aa64mmfr0_el1",
          out(reg) pa_bits
        );
    }

    // Mask off the bits we care about
    pa_bits &= 0xf;

    if pa_bits > 7 {
        // Reserved value
        return 0;
    }

    // Convert the value to the number of bits
    (pa_bits << 2) + 32
}

pub fn get_current_el() -> u64 {
    let mut current_el: u64;
    unsafe {
        asm!(
          "mrs {}, CurrentEL",
          out(reg) current_el
        );
    }

    match current_el {
        0x0C => 3,
        0x08 => 2,
        0x04 => 1,
        _ => panic!("Invalid current EL {}", current_el),
    }
}

pub fn set_tcr(tcr: u64) {
    let current_el = get_current_el();
    unsafe {
        if current_el == 2 {
            asm!(
              "msr tcr_el2, {}",
              in(reg) tcr
            );
        } else if current_el == 1 {
            asm!(
            "msr tcr_el1, {}",
            in(reg) tcr
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb", options(nostack));
    }
}

pub fn set_ttbr0(ttbr0: u64) {
    let current_el = get_current_el();
    unsafe {
        if current_el == 2 {
            asm!(
              "msr ttbr0_el2, {}",
              in(reg) ttbr0
            );
        } else if current_el == 1 {
            asm!(
            "msr ttbr0_el1, {}",
            in(reg) ttbr0
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb", options(nostack));
    }
}

pub fn set_mair(mair: u64) {
    let current_el = get_current_el();
    unsafe {
        if current_el == 2 {
            asm!(
              "msr mair_el2, {}",
              in(reg) mair
            );
        } else if current_el == 1 {
            asm!(
            "msr mair_el1, {}",
            in(reg) mair
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb", options(nostack));
    }
}

pub fn is_mmu_enabled() -> bool {
    let sctlr: u64;
    unsafe {
        asm!(
          "mrs {}, sctlr_el1",
          out(reg) sctlr
        );
    }

    sctlr & 0x1 == 1
}

pub fn enable_mmu() {
    let current_el = get_current_el();
    unsafe {
        if current_el == 2 {
            asm!(
              "mrs x0, sctlr_el2",
              "orr x0, x0, #0x1",
              "tlbi alle2",
              "dsb nsh",
              "isb sy",
              "msr sctlr_el2, x0",
              options(nostack)
            );
        } else if current_el == 1 {
            asm!(
            "mrs x0, sctlr_el1",
            "orr x0, x0, #0x1",
            "tlbi vmalle1",
            "dsb nsh",
            "isb sy",
            "msr sctlr_el1, x0",
            options(nostack)
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb sy", options(nostack));
    }
}

pub fn set_stack_alignment_check(enable: bool) {
    let current_el = get_current_el();
    unsafe {
        if current_el == 2 {
            if enable {
                asm!(
                  "mrs x0, sctlr_el2",
                  "orr x0, x0, #8",
                  "msr sctlr_el2, x0",
                  options(nostack)
                );
            } else {
                asm!(
                  "mrs x0, sctlr_el2",
                  "bic x0, x0, #8",
                  "msr sctlr_el2, x0",
                  options(nostack)
                );
            }
        } else if current_el == 1 {
            if enable {
                asm!(
                  "mrs x0, sctlr_el1",
                  "orr x0, x0, #8",
                  "msr sctlr_el1, x0",
                  options(nostack)
                );
            } else {
                asm!(
                  "mrs x0, sctlr_el1",
                  "bic x0, x0, #8",
                  "msr sctlr_el1, x0",
                  options(nostack)
                );
            }
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("dsb sy", options(nostack));
        asm!("isb sy", options(nostack));
    }
}

pub fn enable_instruction_cache() {
    let current_el = get_current_el();
    unsafe {
        if current_el == 2 {
            asm!(
              "mrs x0, sctlr_el2",
              "orr x0, x0, #0x1000",
              "msr sctlr_el2, x0",
              options(nostack)
            );
        } else if current_el == 1 {
            asm!(
            "mrs x0, sctlr_el1",
            "orr x0, x0, #0x1000",
            "msr sctlr_el1, x0",
            options(nostack)
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb sy", options(nostack));
        asm!("dsb sy", options(nostack));
    }
}

pub fn enable_data_cache() {
    let current_el = get_current_el();
    unsafe {
        if current_el == 2 {
            asm!(
              "mrs x0, sctlr_el2",
              "orr x0, x0, #0x4",
              "msr sctlr_el2, x0",
              options(nostack)
            );
        } else if current_el == 1 {
            asm!(
            "mrs x0, sctlr_el1",
            "orr x0, x0, #0x4",
            "msr sctlr_el1, x0",
            options(nostack)
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb sy", options(nostack));
        asm!("dsb sy", options(nostack));
    }
}

pub fn update_translation_table_entry (translation_table_entry: u64, mva: u64) {
    let current_el = get_current_el();
    let ls_mva = mva << 12;
    unsafe {
        let mut sctlr: u64;
        asm!("dsb     nshst", options(nostack));
        if current_el == 2 {
            asm!(
                "tlbi vae2, {}",
                "mrs {}, sctlr_el2",
                in(reg) ls_mva,
                out(reg) sctlr,
                options(nostack)
            );
        } else if current_el == 1 {
            asm!(
                "tlbi vaae1, {}",
                "mrs {}, sctlr_el1",
                in(reg) ls_mva,
                out(reg) sctlr,
                options(nostack)
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        if sctlr & 1 == 0 {
            asm!(
                "dc ivac, {}",
                in(reg) translation_table_entry,
                options(nostack)
            );
        }
        asm!("dsb nsh", options(nostack));
        asm!("isb", options(nostack));
    }
}
