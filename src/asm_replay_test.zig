const std = @import("std");
const warden_lib = @import("warden.zig");
const print = @import("raw_write.zig").customPrint;
const state_manager = @import("state_manager.zig");

const CallBuffer = state_manager.CallBuffer;

var test_function_counter: u32 = 0;
pub fn test_function(x: *u32, y: u32) callconv(.C) void {
    if (test_function_counter == 0) {
        std.debug.print("First entry, simulating bad behaviour\n", .{});
        test_function_counter = 1;
        asm volatile (".byte 0xcc");
    }
    std.debug.print("x is {d}\n", .{x.*});
    std.debug.print("y is {d}\n", .{y});
}

pub fn main() !void {
    var w = try warden_lib.warden.init(std.heap.page_allocator);
    warden_lib.set_global_warden(&w);
    var n: u32 = 25;
    const m: u32 = 35;
    var test_f = CallBuffer(&test_function){};

    _ = test_f.call(.{ @intFromPtr(&n), m });
    try w.deinit();
    std.debug.print("Sucess - asm_replay\n", .{});
}
