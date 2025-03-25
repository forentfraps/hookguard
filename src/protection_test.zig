const std = @import("std");
const syscall_lib = @import("syscall_wrapper.zig");
const warden_lib = @import("warden.zig");
const print = @import("raw_write.zig").customPrint;
const state_manager = @import("state_manager.zig");

const syscall = syscall_lib.syscall;
const CallBuffer = state_manager.CallBuffer;

var test_function2_counter: u32 = 0;
pub fn test_function2(a: u32, b: u32, c: u32, d: u32, e: u32) callconv(.C) void {
    if (test_function2_counter != 0) {
        _ = warden_lib.global_warden.?.unprotect_global() catch return;
    }
    test_function2_counter = 1;
    std.debug.print("function2 - {d} {d} {d} {d} {d}\n", .{ a, b, c, d, e });
}

pub fn main() !void {
    var w = try warden_lib.warden.init(std.heap.page_allocator);
    warden_lib.set_global_warden(&w);
    var test_f2 = CallBuffer(&test_function2){};
    _ = try w.protect_global();

    try print("test print {d}\n", .{5});

    // _ = try w.unprotect_global();

    _ = test_f2.call(.{ 1, 2, 3, 4, 5 });
    try w.deinit();

    std.debug.print("Sucess - protection\n", .{});
}
