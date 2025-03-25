const std = @import("std");
const syscall_lib = @import("syscall_wrapper.zig");
const winc = @import("Windows.h.zig");
const win = std.os.windows;
const warden_lib = @import("warden.zig");

const syscall_wrapper = syscall_lib.syscall;
const W = std.unicode.utf8ToUtf16LeStringLiteral;

const syscall_manager_error = error{
    SyscallMissing,
};

pub const SyscallManager = struct {
    _NtVirtualProtectMemorySyscall: ?syscall_wrapper = null,
    _NtVirtualAllocateMemorySyscall: ?syscall_wrapper = null,
    _NtOpenProcessSyscall: ?syscall_wrapper = null,

    const Self = @This();

    pub fn addNTVPM(self: *Self, _syscall: syscall_wrapper) void {
        self._NtVirtualProtectMemorySyscall = _syscall;
        return;
    }

    pub fn addNOP(self: *Self, _syscall: syscall_wrapper) void {
        self._NtOpenProcessSyscall = _syscall;
        return;
    }

    pub fn NtOpenProcess(
        self: *Self,
        ProcessHandle: *usize,
        DesiredAcess: usize,
        ObjectAttributes: *anyopaque,
        ClientId: *anyopaque,
    ) !usize {
        if (self._NtOpenProcessSyscall == null) {
            return syscall_manager_error.SyscallMissing;
        }

        return self._NtOpenProcessSyscall.?.call(.{
            @intFromPtr(ProcessHandle),
            DesiredAcess,
            @intFromPtr(ObjectAttributes),
            @intFromPtr(ClientId),
        });
    }

    pub fn NtVirtualProtectMemory(
        self: *Self,
        _: usize,
        BaseAddress: usize,
        NumberOfBytesToProtect: *usize,
        NewAccessProtection: usize,
        OldAccessProtection: *usize,
    ) !usize {
        if (self._NtVirtualProtectMemorySyscall == null) {
            return syscall_manager_error.SyscallMissing;
        }
        return self._NtVirtualProtectMemorySyscall.?.call(.{
            0xFFFFFFFFFFFFFFFF,
            BaseAddress,
            @intFromPtr(NumberOfBytesToProtect),
            NewAccessProtection,
            @intFromPtr(OldAccessProtection),
        });
    }

    pub fn NtAllocateVirtualMemory(
        self: *Self,
        BaseAddress: *?[*]u8,
        ZeroBits: usize,
        RegionSize: *usize,
        AllocationType: usize,
        Protect: usize,
    ) !usize {
        if (self._NtVirtualAllocateMemorySyscall == null) {
            return syscall_manager_error.SyscallMissing;
        }

        return self._NtVirtualAllocateMemorySyscall.?.call(.{
            @intFromPtr(BaseAddress),
            ZeroBits,
            @intFromPtr(RegionSize),
            AllocationType,
            Protect,
        });
    }
};
