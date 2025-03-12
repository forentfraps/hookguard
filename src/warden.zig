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
    InvalidBuffer,
    InvalidDOSHeader,
    InvalidNTSignature,
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
const BASE_RELOCATION_BLOCK = struct {
    PageAddress: u32,
    BlockSize: u32,
};

const BASE_RELOCATION_ENTRY = packed struct {
    Offset: u12,
    Type: u4,
};

pub const MappedMockSection = struct {
    virtual_address: usize,
    size: usize,
    name: []const u8,
    ptr: [*]u8,
};

pub const warden = struct {
    allocator: std.mem.Allocator,

    page_map: PageMap = undefined,
    mod_map: ModuleMap = undefined,

    protected: bool = false,
    nt_scrambled: bool = false,
    init_complete: bool = false,

    protect_syscall: syscall = undefined,
    continue_syscall: syscall = undefined,

    sections: []MappedMockSection = undefined,

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
    pub fn load_initial_exe(self: *Self) !void {
        // Check that the module exists in our modules map.
        var map_iterator = self.mod_map.keyIterator();
        var mod_name: []const u8 = undefined;
        var base_addr: usize = undefined;
        while (true) {
            if (map_iterator.next()) |key| {
                mod_name = key.*;
                if (std.mem.eql(u8, mod_name[mod_name.len - 4 ..], ".exe")) {
                    base_addr = self.mod_map.get(key.*).?.baseAddr;
                    break;
                }
            } else {
                break;
            }
        }
        var mod_name_full: [256]u16 = undefined;
        const mod_name_return: []u16 = @ptrCast(try win.GetModuleFileNameW(null, &mod_name_full, 256));
        const mod_name_full_u8: []u8 = try std.unicode.utf16LeToUtf8Alloc(self.allocator, mod_name_return);
        // Here we assume that the module name is also the filename in the current directory.
        // Adjust this as needed if your modules are in a different location.
        const fs = std.fs.cwd();
        std.debug.print("{s}\n", .{mod_name});
        var file = try fs.openFile(mod_name_full_u8, .{});
        const file_stat = try file.stat();
        const file_size = file_stat.size;
        const buffer = try self.allocator.alloc(u8, file_size);
        _ = try file.readAll(buffer);
        file.close();
        try self.fix_rva(buffer, base_addr);
        return;
    }

    // fix_rva:
    // Parse the DOS header to locate the NT headers, then iterate over all section headers
    // to “fix” their VirtualAddress values. In this placeholder example the fix simply sets
    // the section’s VirtualAddress to be its PointerToRawData plus an offset (0x1000).
    pub fn fix_rva(self: *Self, buffer: []u8, base_addr: usize) !void {
        if (buffer.len < @sizeOf(winc.IMAGE_DOS_HEADER)) {
            return warder_error.InvalidBuffer;
        }
        // Cast the beginning of the buffer as a DOS header.
        const dosHeader: *winc.IMAGE_DOS_HEADER = @alignCast(@ptrCast(buffer.ptr));
        if (dosHeader.e_magic != winc.IMAGE_DOS_SIGNATURE) {
            return warder_error.InvalidDOSHeader;
        }
        const nt_header_offset: usize = @intCast(dosHeader.e_lfanew);
        if (buffer.len < nt_header_offset + @sizeOf(winc.IMAGE_NT_HEADERS)) {
            return warder_error.InvalidBuffer;
        }
        // Obtain a pointer to the NT headers.
        const nt_headers: *winc.IMAGE_NT_HEADERS = @alignCast(@ptrCast(buffer.ptr + nt_header_offset));
        if (nt_headers.Signature != winc.IMAGE_NT_SIGNATURE) {
            return warder_error.InvalidNTSignature;
        }

        const offset = base_addr - nt_headers.OptionalHeader.ImageBase;
        const relocations = nt_headers.OptionalHeader.DataDirectory[winc.IMAGE_DIRECTORY_ENTRY_BASERELOC];
        const optHeaderSize = nt_headers.FileHeader.SizeOfOptionalHeader;
        const sections_ptr: *align(1) winc.IMAGE_SECTION_HEADER = (@ptrCast((@as([*]u8, @constCast(@ptrCast(&nt_headers.OptionalHeader)))) + optHeaderSize));
        // Create a slice over the section headers.
        const numSections = nt_headers.FileHeader.NumberOfSections;
        const sections: [*]align(1) winc.IMAGE_SECTION_HEADER = @ptrCast(sections_ptr);
        var raw_reloc_ptr: [*]u8 = undefined;
        self.sections = try self.allocator.alloc(MappedMockSection, numSections);

        for (sections[0..numSections], 0..) |section, i| {
            const section_name_trimmed = (&section.Name)[0..std.mem.len(@as([*:0]u8, @constCast(@ptrCast(&section.Name))))];
            self.sections[i] =
                MappedMockSection{
                    .virtual_address = section.VirtualAddress,
                    .name = section_name_trimmed,
                    .size = section.SizeOfRawData,
                    .ptr = buffer[section.PointerToRawData..].ptr,
                };
            if (std.mem.eql(u8, section_name_trimmed, ".reloc".ptr[0..6])) {
                raw_reloc_ptr = buffer[section.PointerToRawData..].ptr;
                std.debug.print("raw_reloc_ptr {*}\n", .{raw_reloc_ptr});
            }
        }
        const relocation_table: [*]u8 = raw_reloc_ptr;
        var relocations_processed: u32 = 0;
        std.debug.print("virt addr of reloca table: {*}\n", .{relocation_table});

        while (relocations_processed < relocations.Size) {
            const relocation_block: *align(1) BASE_RELOCATION_BLOCK = @ptrCast(@alignCast(relocation_table[relocations_processed..]));
            relocations_processed += @sizeOf(BASE_RELOCATION_BLOCK);
            const relocations_count = (relocation_block.BlockSize - @sizeOf(BASE_RELOCATION_BLOCK)) / @sizeOf(BASE_RELOCATION_ENTRY);
            const relocation_entries: [*]align(1) BASE_RELOCATION_ENTRY = @ptrCast(@alignCast(relocation_table[relocations_processed..]));

            for (0..relocations_count) |entry_index| {
                if (relocation_entries[entry_index].Type != 0) {
                    const relocation_rva: usize = relocation_block.PageAddress + relocation_entries[entry_index].Offset;
                    std.debug.print("address to fix is {x} off the base\n", .{relocation_rva});
                    //log.info("Value before rva is {x} changing to {*}\n", .{ ptr.*, ptr });
                    var section_pointer: [*]u8 = undefined;
                    for (self.sections) |section| {
                        if (relocation_rva >= section.virtual_address and relocation_rva <= (section.virtual_address + section.size)) {
                            section_pointer = section.ptr;
                            break;
                        }
                    }
                    const ptr: *align(1) usize = @ptrCast(section_pointer[relocation_rva..]);
                    ptr.* = ptr.* + offset;

                    //address_to_patch += offset;

                } else {
                    //log.info("Type ABSOLUT offset: {d}\n", .{relocation_entries[entry_index].Offset});
                }
                relocations_processed += @sizeOf(BASE_RELOCATION_ENTRY);
            }
            //log.info("block proc\n", .{});
        }
    }
    // load_initial_exe
    // fix_rva_imports
    //
    // backtrace_evil_call
    //
    // map_address_to_mod
    // map_address_to_page
    // map_page_to_mod
    // protect_global
    // protect_page
    // unprotect_page
    // unprotect_global
    // prepare_to_scramble_nt
    // scramble_nt
    // unscramble_nt_veh
    // unscramble_nt
    //
};
