const std = @import("std");
const syscall_lib = @import("syscall_wrapper.zig");
const winc = @import("Windows.h.zig");
const win = std.os.windows;
const warden_lib = @import("warden.zig");

const syscall = syscall_lib.syscall;
const W = std.unicode.utf8ToUtf16LeStringLiteral;
const state_manager = @import("state_manager.zig");
const CallBuffer = state_manager.CallBuffer;

const print = @import("raw_write.zig").customPrint;

pub fn main() !void {
    var w = try warden_lib.warden.init(std.heap.page_allocator);
    warden_lib.set_global_warden(&w);
    try w.deinit();
}
