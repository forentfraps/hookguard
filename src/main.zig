const std = @import("std");
const winc = @import("Windows.h.zig");
const win = std.os.windows;
const W = std.unicode.utf8ToUtf16LeStringLiteral;
const root = @import("root.zig");
const CallBuffer = root.StateManagerLib.CallBuffer;

pub fn main() !void {
    var w = try root.WardenLib.warden.init(std.heap.page_allocator);
    root.WardenLib.set_global_warden(&w);
    try w.deinit();
}
