const std = @import("std");
const syscall_lib = @import("syscall.zig");
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

    const Self = @This();

    pub fn addNTVPM(self: *Self, _syscall: syscall_wrapper) void {
        self.NtVirtualProtectMemorySyscall = _syscall;
        return;
    }

    pub fn NtVirtualProtectMemory(
        self: *Self,
        ProcessHandle: usize,
        BaseAddress: [*]u8,
        NumberOfBytesToProtect: *usize,
        NewAccessProtection: usize,
        OldAccessProtection: *usize,
    ) !win.NTSTATUS {
        if (self._NtVirtualProtectMemorySyscall == null) {
            return syscall_manager_error.SyscallMissing;
        }
        return self._NtVirtualProtectMemory.call(.{
            ProcessHandle,
            BaseAddress,
            NumberOfBytesToProtect,
            NewAccessProtection,
            OldAccessProtection,
        });
    }

    pub fn NtAllocateVirtualMemory(
        self: *Self,
        BaseAddress: *?[*]u8,
        ZeroBits: usize,
        RegionSize: *usize,
        AllocationType: usize,
        Protect: usize,
    ) !win.NTSTATUS {
        if (self._NtVirtualAllocateMemorySyscall == null) {
            return syscall_manager_error.SyscallMissing;
        }

        return self._NtVirtualAllocateMemorySyscall.call(.{
            BaseAddress,
            ZeroBits,
            RegionSize,
            AllocationType,
            Protect,
        });
    }
};
