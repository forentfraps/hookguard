const std = @import("std");
const warden_lib = @import("warden.zig");

pub const CustomWriter = struct {
    /// The error set for this writer.
    pub const Error = anyerror;
    pub const Self = @This();

    /// The method that `std.fmt.format` calls to emit data.
    /// Must match signature: `fn writeAll(self: *CustomWriter, bytes: []const u8) !Error`.
    pub fn writeAll(_: Self, bytes: []const u8) !void {
        // For example, call a global function that writes bytes somewhere:
        // If you can fail, you can do `return error.Lol;` on failure.
        // Otherwise, just "try" as needed:
        warden_lib.global_warden.?.raw_printer(bytes);

        return; // no error
    }
    pub fn writeBytesNTimes(self: Self, bytes: []const u8, n: usize) anyerror!void {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            try self.writeAll(bytes);
        }
    }
};

/// A function that behaves like `std.debug.print` but sends data to `CustomWriter`.
pub fn customPrint(comptime fmt: []const u8, args: anytype) !void {
    const writer = CustomWriter{};
    // IMPORTANT: pass &writer so `std.fmt.format` can call writeAll on *CustomWriter
    try std.fmt.format(writer, fmt, args);
}
