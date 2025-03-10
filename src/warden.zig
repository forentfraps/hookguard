const std = @import("std");
const syscall_lib = @import("syscall.zig");
const winc = @import("Windows.h.zig");
const win = std.os.windows;

const syscall = syscall_lib.syscall;
const W = std.unicode.utf8ToUtf16LeStringLiteral;

var global_warden: ?warden = null;

const warder_error = error{
    SnapshotFail,
    Module32FirstFail,
};

// pub fn VEH_warden(exception: *win.EXCEPTION_POINTERS) usize {
//     const exception_record = exception.ExceptionRecord;
//     const _context = exception.ContextRecord;
// }
pub const PageInfo = struct {
    baseAddr: usize,
    regionSize: usize,
    access: u32,

    const Self = @This();
};

const PageMap = std.AutoHashMap(usize, PageInfo);
pub const ModuleInfo = struct {
    baseAddr: usize,
    size: usize,
    // A dynamic list of pages that are mapped into this module.
    pages: std.ArrayList(PageInfo),
};

const ModuleMap = std.StringHashMap(ModuleInfo);

pub const warden = struct {
    allocator: std.mem.Allocator,

    page_map: PageMap = undefined,
    mod_map: ModuleMap = undefined,

    protect_syscall: syscall = undefined,
    continue_syscall: syscall = undefined,

    const Self = @This();

    // get_all_pages

    pub fn enumerate_memory(self: *Self) !void {
        const allocator = self.allocator;
        var pages_map = std.AutoHashMap(usize, PageInfo).init(allocator);

        // Retrieve system information to get the address space boundaries.
        var sys_info: win.SYSTEM_INFO = undefined;
        win.kernel32.GetSystemInfo(&sys_info);

        var page_count: usize = 0;

        // The addresses are represented as numbers for iteration.
        var current_addr: usize = @intFromPtr(sys_info.lpMinimumApplicationAddress);
        const max_addr: usize = @intFromPtr(sys_info.lpMaximumApplicationAddress);

        while (current_addr < max_addr) {
            var mbi: win.MEMORY_BASIC_INFORMATION = undefined;
            const mbi_size = @sizeOf(win.MEMORY_BASIC_INFORMATION);
            const query_result =
                try win.VirtualQuery(@as(win.PVOID, @ptrFromInt(current_addr)), &mbi, mbi_size);
            if (query_result == 0) break; // No more regions to query

            // Check if the region is committed (i.e. allocated).
            if (mbi.State == win.MEM_COMMIT) {
                const key = @intFromPtr(mbi.BaseAddress);
                const page = PageInfo{
                    .baseAddr = key,
                    .regionSize = mbi.RegionSize,
                    .access = mbi.Protect,
                };
                // Insert into the hashmap. If the key already exists, this returns an error.
                try pages_map.put(key, page);
                page_count += 1;
            }

            // Move to the next region.
            current_addr = @intFromPtr(mbi.BaseAddress) + mbi.RegionSize;
        }
        self.page_map = pages_map;
        std.debug.print("Pages in total: {d}\n", .{page_count});
    }
    // Enumerate all loaded modules (the .exe and .dlls) for the local process.
    // For each module, we create an entry in a map keyed by the module name.
    // The ModuleInfo struct stores the module’s base address, its size, and a list of
    // PageInfo structs that fall within the module’s address range.
    pub fn enumerate_modules(self: *Self) !void {
        var modules_map = ModuleMap.init(self.allocator);

        // Get the current process ID.
        // TODO no winapi
        const currentPID = win.GetCurrentProcessId();

        // Create a snapshot of all modules in the current process.
        // TODO no winapi
        const snapshot = win.kernel32.CreateToolhelp32Snapshot(win.TH32CS_SNAPMODULE | win.TH32CS_SNAPMODULE32, currentPID);
        if (snapshot == win.INVALID_HANDLE_VALUE) {
            return warder_error.SnapshotFail;
        }
        defer win.CloseHandle(snapshot);

        var module_entry: win.MODULEENTRY32 = undefined;
        module_entry.dwSize = @sizeOf(win.MODULEENTRY32);
        if (win.kernel32.Module32First(snapshot, &module_entry) == 0) {
            return warder_error.Module32FirstFail;
        }

        // Loop over each module.
        while (true) {
            // Obtain the module name.
            // Assume that szModule is a null-terminated C string.
            const uncut_modname: [*:0]const u8 = @ptrCast(&module_entry.szModule);
            const mod_len = std.mem.len(uncut_modname);
            const modName = module_entry.szModule[0..mod_len];

            const baseAddr = @intFromPtr(module_entry.modBaseAddr);
            const modSize = module_entry.modBaseSize;

            // Create a ModuleInfo instance with an empty list of pages.
            var moduleInfo = ModuleInfo{
                .baseAddr = baseAddr,
                .size = modSize,
                .pages = std.ArrayList(PageInfo).init(self.allocator),
            };

            // Iterate over all pages from the pages_map and add those that fall within this module.
            var it = self.page_map.iterator();
            while (it.next()) |entry| {
                const pageAddr = entry.key_ptr.*;
                if (pageAddr >= baseAddr and pageAddr < baseAddr + modSize) {
                    try moduleInfo.pages.append(entry.value_ptr.*);
                }
            }

            // Allocate and copy the module name into our allocator.
            const name_len = modName.len;
            var name_buf = try self.allocator.alloc(u8, name_len);
            std.mem.copyForwards(u8, name_buf, modName);
            const name_slice = name_buf[0..name_len];
            std.debug.print(
                "MOdule logged: {s} at {x} with {d} pages\n",
                .{ modName, moduleInfo.baseAddr, moduleInfo.pages.items.len },
            );

            try modules_map.put(name_slice, moduleInfo);

            // TODO this is also a winapi macro
            if (win.kernel32.Module32Next(snapshot, &module_entry) == 0) break;
        }

        self.mod_map = modules_map;
        return;
    }

    // load_initial_exe
    // load_RVA_list
    //
    //
    //
    //backtrace_evil_call
    //
    // map_address_to_mod
    // map_address_to_page
    // map_page_to_mod
    // protect_global
    // protect_page
    // unprotect_page
    // unprotect_global
    // scramble_nt
    // unscramble_nt_veh
    // unscramble_nt
    //
};
