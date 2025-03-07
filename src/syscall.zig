const std = @import("std");

extern fn syscall_wrapper(syscall_number: u32, argcount: usize, args: [*]usize) usize;

pub const syscallError = error{BadFunction};

pub const syscall = struct {
    syscall_number: u16,

    const Self = @This();

    pub fn init(syscall_number: u16) Self {
        return .{ .syscall_number = syscall_number };
    }

    pub fn call(self: *syscall, args: anytype) usize {
        // Use comptime reflection to build an array of argument values.
        const fields = std.meta.fields(@TypeOf(args));
        const arg_count = fields.len;
        var values: [arg_count]usize = undefined;
        var i: usize = 0;
        inline for (fields) |field| {
            values[i] = @field(args, field.name);
            i += 1;
        }
        return syscall_wrapper(self.syscall_number, arg_count, &values);
    }

    pub fn fetch(func_ptr: [*]u8) !Self {
        //4C 8B D1 B8 ?? ??

        const magic: u32 = 0xB8D18B4C;
        const magic_ptr: *u32 = @alignCast(@ptrCast(func_ptr));

        if (magic_ptr.* != magic) {
            return syscallError.BadFunction;
        }

        const syscall_number_ptr: *u16 = @alignCast(@ptrCast(func_ptr[4..]));
        const syscall_number: u16 = syscall_number_ptr.*;

        return syscall.init(syscall_number);
    }
};
pub fn set_registers(arg1: u64, arg2: u64) void {
    asm volatile (
        \\mov %[val1], %%rcx
        \\mov %[val2], %%rax
        : // No output operands
        : [val1] "r" (arg1),
          [val2] "r" (arg2), // Input operands
        : "rcx", "rax" // Clobbered registers
    );
}
