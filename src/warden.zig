const std = @import("std");
const syscall_lib = @import("syscall.zig");
const winc = @import("Windows.h.zig");
const win = std.os.windows;

const syscall = syscall_lib.syscall;
const W = std.unicode.utf8ToUtf16LeStringLiteral;

var global_warden: ?warden = null;

pub fn VEH_warden(exception: *win.EXCEPTION_POINTERS) usize{
    const exception_record = exception.ExceptionRecord;
    const context = exception.ContextRecord;
}

const warden = struct{
    protect_syscall: syscall,
    continue_syscall: syscall,

    const Self = @This();


    // get_all_pages
    // get_all_mods
    //
    // map_address_to_mod
    // map_address_to_page
    // map_page_to_mod
    // protect_global
    // protect_page
    // unprotect_page
    // unprotect_global
    // scramble_nt
    // unscramble_nt_veh
    // unscramble_nt
    //
};
