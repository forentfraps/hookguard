const std = @import("std");
const hookguard = @import("hookguard");
const warden_lib = hookguard.WardenLib;
const state_manager = hookguard.StateManagerLib;

const CallBuffer = state_manager.CallBuffer;

var test_function2_counter: u32 = 0;
pub fn test_function2(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32) callconv(.c) void {
    if (test_function2_counter != 0) {
        _ = warden_lib.global_warden.?.unprotect_global() catch return;
    }
    test_function2_counter = 1;
    std.debug.print("function2 - {d} {d} {d} {d} {d} {d}\n", .{ a, b, c, d, e, f });
}

pub fn main() !void {
    std.debug.print("\n---Protection TEST----\n", .{});
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();

    var w = try warden_lib.warden.init(allocator);
    warden_lib.set_global_warden(&w);
    var test_f2 = CallBuffer(&test_function2){};
    _ = try w.protect_global();

    // _ = try w.unprotect_global();

    _ = test_f2.call(.{ 1, 2, 3, 4, 5, 6 });
    try w.deinit();

    std.debug.print("Sucess - protection\n", .{});
    _ = gpa.detectLeaks();
}
