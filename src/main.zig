const std = @import("std");
const syscall_lib = @import("syscall.zig");
const winc = @import("Windows.h.zig");
const win = std.os.windows;
const warden_lib = @import("warden.zig");

const syscall = syscall_lib.syscall;
const W = std.unicode.utf8ToUtf16LeStringLiteral;

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
    var w = warden_lib.warden{ .allocator = std.heap.page_allocator };
    try w.enumerate_memory();
    try w.enumerate_modules();
    try w.load_initial_exe();
}
