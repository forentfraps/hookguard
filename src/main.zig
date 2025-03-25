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
    const ntdll = win.kernel32.GetModuleHandleW(W("ntdll.dll")).?;
    const ntqsi: [*]u8 = @ptrCast(win.kernel32.GetProcAddress(ntdll, "NtQuerySystemInformation").?);

    var s = try syscall.fetch(ntqsi);
    var storage: u64 = 0;
    var buf: [20]u8 = undefined;
    var result = s.call(.{ 0, @intFromPtr(&buf), 20, @intFromPtr(&storage) });
    std.debug.print("Syscall returned: {x} desired size is: {d}\n", .{ result, storage });
    const alloc = std.heap.page_allocator;
    var new_buf = std.ArrayList(u8).init(alloc);
    try new_buf.resize(storage);
    result = s.call(.{ 0, @intFromPtr(&new_buf), storage, @intFromPtr(&storage) });

    std.debug.print("Syscall returned: {x}\n", .{result});

    // std.debug.print("Reprotecting ntdll\n");
    var w = try warden_lib.warden.init(std.heap.page_allocator);
    warden_lib.set_global_warden(&w);
    // _ = win.kernel32.AddVectoredExceptionHandler(1000, &warden_lib.VEH_warden);
    // var n: u32 = 25;
    // const m: u32 = 35;
    //
    // var test_f = CallBuffer(&test_function){};
    // var test_f2 = CallBuffer(&test_function2){};
    // _ = test_f.call(.{ @intFromPtr(&n), m });
    // _ = test_f2.call(.{ 1, 2, 3, 4, 5 });
    _ = try w.protect_global();

    try print("test print {d}\n", .{storage});

    _ = try w.unprotect_global();

    // _ = test_f2.call(.{ 1, 2, 3, 4, 5 });
}

var tries: i8 = 0;

pub fn test_function(x: *u32, y: u32) callconv(.C) void {
    if (tries == 0) {
        std.debug.print("First entry, simulating bad behaviour\n", .{});
        tries = 1;
        asm volatile (".byte 0xcc");
    }
    tries = 0;
    std.debug.print("x is {d}\n", .{x.*});
    std.debug.print("y is {d}\n", .{y});
}

pub fn test_function2(a: u32, b: u32, c: u32, d: u32, e: u32) callconv(.C) void {
    if (tries != 0) {
        _ = warden_lib.global_warden.?.unprotect_global() catch return;
    }
    tries = 1;
    std.debug.print("function2 - {d} {d} {d} {d} {d}\n", .{ a, b, c, d, e });
}
