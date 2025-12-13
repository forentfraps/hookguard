const std = @import("std");
const hookguard = @import("hookguard");
const warden_lib = hookguard.WardenLib;
const state_manager = hookguard.StateManagerLib;

const CallBuffer = state_manager.CallBuffer;

var test_function_counter: u32 = 0;
pub fn test_function(x: *u32, y: u32) callconv(.c) void {
    if (test_function_counter == 0) {
        std.debug.print("First entry, simulating bad behaviour\n", .{});
        test_function_counter = 1;
        asm volatile (".word 0x01cd");
    }
    std.debug.print("x is {d}\n", .{x.*});
    std.debug.print("y is {d}\n", .{y});
}

pub fn main() !void {
    std.debug.print("\n---asm replay TEST----\n", .{});
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    var w = try warden_lib.warden.init(allocator);
    warden_lib.set_global_warden(&w);
    var n: u32 = 25;
    const m: u32 = 35;
    var test_f = CallBuffer(&test_function){};

    _ = test_f.call(.{ @intFromPtr(&n), m });
    try w.deinit();
    std.debug.print("Sucess - asm_replay\n", .{});
    _ = gpa.detectLeaks();
}
