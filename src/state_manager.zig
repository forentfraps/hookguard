const std = @import("std");
const syscall_lib = @import("syscall.zig");
const winc = @import("Windows.h.zig");
const win = std.os.windows;
const warden_lib = @import("warden.zig");

const syscall = syscall_lib.syscall;
const W = std.unicode.utf8ToUtf16LeStringLiteral;

extern fn save_preserved_registers(*usize, *usize, *usize) void;
extern fn load_preserved_registers(usize, usize, usize) void;
extern fn retry_asm(*anyopaque) void;

const state_manager_error = error{
    InvalidFuncPtr,
    ArgMismatch,
};

pub fn CallBuffer(func_ptr: anytype, arg: anytype, warden: warden_lib.warden) !type {
    const func_type = @TypeOf(func_ptr);
    const arg_type = @TypeOf(arg);
    const funcTypeInfo = @typeInfo(func_type);
    var fnInfo: type = undefined;
    switch (funcTypeInfo) {
        .Pointer => |ptrInfo| {
            switch (@typeInfo(ptrInfo.child)) {
                .Fn => |fi| {
                    fnInfo = fi;
                },
                else => @compileError("Not a function pointer was provided"),
            }
        },
        else => @compileError("Not a function pointer"),
    }

    const fnArgs = fnInfo.params;
    const fnReturnType = fnInfo.return_type.?;

    const argTypeInfo = @typeInfo(arg_type);
    var arg_len: comptime_int = 0;
    _ = switch (argTypeInfo) {
        .Struct => |structInfo| {
            if (structInfo.fields.len != fnArgs.len) {
                @compileError("Argument mismatch");
            }
            // Compare each field's type with the corresponding function parameter.
            for (fnArgs, 0..) |fn_arg, i| {
                const field = structInfo.fields[i];
                if (field.field_type != fn_arg.type) {
                    @compileError("Argument mismatch");
                }
                arg_len += 1;
                // Optional: If you want to match names as well,
                // you can compare `field.name` with `fn_arg.name`.
            }
        },
        else => @compileError("Argument mismatch"),
    };

    // If we got here, the argument matches.
    return struct {
        registers: [9]usize = undefined,
        func_ptr: func_type = func_ptr,
        arg_count: usize = fnArgs.len.fields.len,
        arg: arg_type = arg,
        // TODO add support for xmm+ registers
        arg_sizes: [fnArgs.len.fields.len]u8 = arg_size_closure: {
            var local_arg_sizes: [fnArgs.len.fields]u8 = undefined;
            for (fnArgs, 0..) |fn_arg, i| {
                local_arg_sizes[i] = @truncate(@sizeOf(fn_arg.type));
            }

            break :arg_size_closure local_arg_sizes;
        },

        warden: *warden_lib.warden = warden,

        pub fn change_arg(self: *@This(), new_arg: arg_type) fnReturnType {
            self.arg = new_arg;
        }
        pub fn call(self: *@This()) void {
            comptime {
                // Get the fields of the argument struct.
                const argInfo = @typeInfo(@TypeOf(self.arg));
                const fields = switch (argInfo) {
                    .Struct => |s| s.fields,
                    else => @compileError("Argument is not a struct"),
                };
                self.warden.register_call(&self);
                save_preserved_registers(&self.rsp, &self.rbp, &self.r15);
                // Manually dispatch based on the number of arguments.
                const return_val = switch (fields.len) {
                    0 => self.func_ptr(),
                    1 => self.func_ptr(@field(self.arg, fields[0].name)),
                    2 => self.func_ptr(@field(self.arg, fields[0].name), @field(self.arg, fields[1].name)),
                    3 => self.func_ptr(@field(self.arg, fields[0].name), @field(self.arg, fields[1].name), @field(self.arg, fields[2].name)),
                    4 => self.func_ptr(@field(self.arg, fields[0].name), @field(self.arg, fields[1].name), @field(self.arg, fields[2].name), @field(self.arg, fields[3].name)),
                    5 => self.func_ptr(@field(self.arg, fields[0].name), @field(self.arg, fields[1].name), @field(self.arg, fields[2].name), @field(self.arg, fields[3].name), @field(self.arg, fields[4].name)),
                    else => @compileError("Unsupported number of arguments in CallBuffer.call"),
                };
                self.warden.deregister_call(&self);
                return return_val;
            }
        }

        pub fn retry(self: *@This()) noreturn {
            retry_asm(self);
        }
    };
}

const StateManager = struct {};
