const std = @import("std");
const syscall_lib = @import("syscall_wrapper.zig");
const winc = @import("Windows.h.zig");
const win = std.os.windows;
const warden_lib = @import("warden.zig");

const syscall = syscall_lib.syscall;
const W = std.unicode.utf8ToUtf16LeStringLiteral;

extern fn call_asm(*const anyopaque) usize;

const state_manager_error = error{
    InvalidFuncPtr,
    ArgMismatch,
};

pub fn CallBuffer(func_ptr: anytype) type {
    const func_type = @TypeOf(func_ptr);
    const funcTypeInfo = @typeInfo(func_type);
    var fnInfo: std.builtin.Type.Fn = undefined;
    switch (funcTypeInfo) {
        .pointer => |ptrInfo| {
            switch (@typeInfo(ptrInfo.child)) {
                .@"fn" => |fi| {
                    fnInfo = fi;
                },
                else => @compileError("Not a function pointer was provided"),
            }
        },
        else => @compileError("Not a function pointer"),
    }

    const fnArgs = fnInfo.params;

    // @compileLog(arg_type);

    return struct {
        registers: [9]usize = undefined,
        func_ptr: func_type = func_ptr,
        arg_count: usize = fnArgs.len,
        arg: [fnArgs.len]usize = undefined,

        pub fn call(self: *@This(), new_arg: [fnArgs.len]usize) usize {
            self.arg = new_arg;
            warden_lib.global_warden.?.register_call(self) catch {
                return 0;
            };
            const return_val: usize = call_asm(self);
            warden_lib.global_warden.?.deregister_call(self);
            return return_val;
        }
    };
}

const StateManager = struct {};
