const std = @import("std");
const syscall_lib = @import("syscall.zig");
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

pub fn CallBuffer(func_ptr: anytype, arg: anytype) type {
    const func_type = @TypeOf(func_ptr);
    const arg_type = @TypeOf(arg);
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

    const argTypeInfo = @typeInfo(arg_type);
    var arg_len: comptime_int = 0;
    _ = switch (argTypeInfo) {
        .@"struct" => |structInfo| {
            if (structInfo.fields.len != fnArgs.len) {
                @compileError("Argument mismatch");
            }
            // Compare each field's type with the corresponding function parameter.
            for (fnArgs, 0..) |fn_arg, i| {
                const field = structInfo.fields[i];
                // @compileLog(field.type);
                // @compileLog(fn_arg.type.?);
                if (field.type != fn_arg.type.?) {
                    @compileError("Argument mismatch");
                }
                arg_len += 1;
                // Optional: If you want to match names as well,
                // you can compare `field.name` with `fn_arg.name`.
            }
        },
        else => @compileError("Argument mismatch"),
    };
    // @compileLog(arg_type);

    // If we got here, the argument matches.
    return struct {
        registers: [9]usize = undefined,
        func_ptr: func_type = func_ptr,
        arg_count: usize = fnArgs.len,
        // arg_sizes: [fnArgs.len]u8 = arg_size_closure: {
        //     var local_arg_sizes: [fnArgs.len]u8 = undefined;
        //     for (fnArgs, 0..) |fn_arg, i| {
        //         local_arg_sizes[i] = @truncate(@sizeOf(fn_arg.type.?));
        //     }
        //
        //     break :arg_size_closure local_arg_sizes;
        // },
        arg: [fnArgs.len]usize = arg_cast_closure: {
            var local_arg_cast: [fnArgs.len]usize = undefined;
            for (fnArgs, 0..) |fn_arg, i| {
                switch (fn_arg.type.?) {
                    std.builtin.Type.Pointer => {
                        local_arg_cast[i] = @intFromPtr(arg[i]);
                    },
                    else => {
                        local_arg_cast[i] = @intCast(arg[i]);
                    },
                    // else => {
                    //     @compileLog(fn_arg.type.?);
                    //     @compileError("UNSUPPORTED TYPE");
                    // },
                }
            }
            break :arg_cast_closure local_arg_cast;
        },
        // TODO add support for xmm+ registers

        pub fn change_arg(self: *@This(), new_arg: arg_type) void {
            self.arg = new_arg;
        }
        pub fn call(self: *@This()) usize {
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
