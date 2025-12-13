const std = @import("std");
const winc = @import("Windows.h.zig");
const win = std.os.windows;
const state_manager = @import("state_manager.zig");
const syscall_manager_lib = @import("syscall_manager");

const Syscall = syscall_manager_lib.Syscall;
const SyscallManager = syscall_manager_lib.SyscallManager;
const W = std.unicode.utf8ToUtf16LeStringLiteral;
const Walloc = std.unicode.utf8ToUtf16LeAllocZ;

extern fn retry_asm(*const anyopaque) void;

pub var global_warden: ?*warden = null;

pub fn set_global_warden(w: *warden) void {
    global_warden = w;
}

const ClientId = struct {
    UniqueProcess: usize,
    UniqueThread: usize,
};

const warder_error = error{
    SnapshotFail,
    Module32FirstFail,
    InvalidBuffer,
    InvalidDOSHeader,
    InvalidNTSignature,
};

extern fn _MEH_warden_asm() callconv(.c) void;

comptime {
    @export(&MEH_warden, .{
        .name = "MEH_warden",
        .linkage = .strong,
    });
}
pub fn MEH_warden(_: *win.EXCEPTION_RECORD, _: *win.CONTEXT) callconv(.c) c_long {
    // MASTER Exception Handler
    //0x48, 0x8D, 0x84, 0x24, 0xF0, 0x04, 0x00, 0x00, 0x48, 0x8D, 0x0C, 0x24

    // std.debug.print("Excpetion occured: {x} - {*}\n", .{ er.ExceptionCode, er.ExceptionAddress }) ;
    global_warden.?.check_exe_sections() catch {};
    retry_asm(global_warden.?.callbuff.items[global_warden.?.callbuff.items.len - 1]);

    return win.EXCEPTION_CONTINUE_SEARCH;
}
pub const PageInfo = struct {
    baseAddr: usize,
    regionSize: usize,
    access: u32,
    unprotected_access: u32,
};

const PageMap = std.AutoHashMap(usize, *PageInfo);
pub const ModuleInfo = struct {
    baseAddr: usize,
    size: usize,
    // A dynamic list of pages that are mapped into this module.
    pages: std.ArrayList(*PageInfo),
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

    //contains dynamically allocated pages
    page_map: PageMap = undefined,

    //pages are references from the map
    mod_map: ModuleMap = undefined,

    protected: bool = false,
    nt_scrambled: bool = false,
    init_complete: bool = false,

    exe_buf: []u8 = undefined,
    sections: []MappedMockSection = undefined,
    current_mod: usize = undefined,

    ntdll_buffer: [0x11]u8 = undefined,
    ntdll_special_page: usize = undefined,

    //fully on the stack
    syscall_manager: SyscallManager = undefined,

    // callbuff is using FixedBufferAllocator
    // because reallocation could be used
    // when protected
    callbuff: std.ArrayList(*const anyopaque) = undefined,

    _fba: std.heap.FixedBufferAllocator = undefined,
    _fba_buf: [0x4000]u8 = undefined,
    raw_allocator: std.mem.Allocator = undefined,

    const Self = @This();

    pub fn deinit(self: *Self) !void {
        _ = try self.unprotect_global();
        try self.unpatch_ntdll();
        var page_iterator = self.page_map.iterator();
        while (page_iterator.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.page_map.deinit();
        var mod_iterator = self.mod_map.iterator();
        while (mod_iterator.next()) |entry| {
            entry.value_ptr.pages.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.mod_map.deinit();
        // self._fba.deinit();

        self.allocator.free(self.exe_buf);
        self.allocator.free(self.sections);
        global_warden = null;
    }

    pub fn init(allocator: std.mem.Allocator) !Self {
        var self = Self{ .allocator = allocator };
        _ = try self.enumerate_memory();
        _ = try self.enumerate_modules();
        _ = try self.load_initial_exe();
        self.syscall_manager = SyscallManager.init();
        const ntdll = win.kernel32.GetModuleHandleW(W("ntdll.dll")).?;

        const ntpvm: [*]u8 = @ptrCast(win.kernel32.GetProcAddress(ntdll, "ZwProtectVirtualMemory").?);
        const ntop: [*]u8 = @ptrCast(win.kernel32.GetProcAddress(ntdll, "NtOpenProcess").?);
        const ntwf: [*]u8 = @ptrCast(win.kernel32.GetProcAddress(ntdll, "NtWriteFile").?);

        try self.syscall_manager.addFromStub(.NtVirtualProtectMemory, ntpvm);
        try self.syscall_manager.addFromStub(.NtOpenProcess, ntop);
        try self.syscall_manager.addFromStub(.NtWriteFile, ntwf);

        try self.patch_ntdll();
        self._fba = std.heap.FixedBufferAllocator.init(&self._fba_buf);
        self.raw_allocator = self._fba.allocator();
        self.callbuff = try std.ArrayList(*const anyopaque).initCapacity(self.raw_allocator, 1);

        self.get_current_mod();

        self.init_complete = true;
        return self;
    }

    fn enumerate_memory(self: *Self) !void {
        const allocator = self.allocator;
        var pages_map = PageMap.init(allocator);

        // Retrieve system information to get the address space boundaries.
        var sys_info: win.SYSTEM_INFO = undefined;
        win.kernel32.GetSystemInfo(&sys_info);

        var page_count: usize = 0;

        // The addresses are represented as numbers for iteration.
        var current_addr: usize = @intFromPtr(sys_info.lpMinimumApplicationAddress);
        const max_addr: usize = @intFromPtr(sys_info.lpMaximumApplicationAddress);
        const page_size: usize = sys_info.dwPageSize;

        while (current_addr < max_addr) {
            var mbi: win.MEMORY_BASIC_INFORMATION = undefined;
            const mbi_size = @sizeOf(win.MEMORY_BASIC_INFORMATION);
            const query_result =
                try win.VirtualQuery(@as(win.PVOID, @ptrFromInt(current_addr)), &mbi, mbi_size);
            if (query_result == 0) break; // No more regions to query

            // Check if the region is committed (i.e. allocated).

            if (mbi.State == win.MEM_COMMIT) {
                const page_per_block = mbi.RegionSize / page_size;
                for (0..page_per_block) |i| {
                    const key = @intFromPtr(mbi.BaseAddress) + page_size * i;
                    const page = try self.allocator.create(PageInfo);
                    page.* = PageInfo{
                        .baseAddr = key,
                        .regionSize = page_size,
                        .access = mbi.Protect,
                        .unprotected_access = mbi.Protect,
                    };
                    // Insert into the hashmap. If the key already exists, this returns an error.
                    try pages_map.put(key, page);
                    page_count += 1;
                }
            }

            // Move to the next region.
            current_addr = @intFromPtr(mbi.BaseAddress) + mbi.RegionSize;
        }
        self.page_map = pages_map;
    }
    // Enumerate all loaded modules (the .exe and .dlls) for the local process.
    // For each module, we create an entry in a map keyed by the module name.
    // The ModuleInfo struct stores the module’s base address, its size, and a list of
    // PageInfo structs that fall within the module’s address range.
    fn enumerate_modules(self: *Self) !void {
        var modules_map = ModuleMap.init(self.allocator);

        // Get the current process ID.
        // TODO no winapi
        const currentPID = win.GetCurrentProcessId();

        // Create a snapshot of all modules in the current process.
        // TODO no winapi
        const snapshot =
            win.kernel32.CreateToolhelp32Snapshot(win.TH32CS_SNAPMODULE | win.TH32CS_SNAPMODULE32, currentPID);
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
                .pages = try std.ArrayList(*PageInfo).initCapacity(self.allocator, 1),
            };

            // Iterate over all pages from the pages_map and add those that fall within this module.
            var it = self.page_map.iterator();
            while (it.next()) |entry| {
                const pageAddr = entry.key_ptr.*;
                if (pageAddr >= baseAddr and pageAddr < baseAddr + modSize) {
                    try moduleInfo.pages.append(self.allocator, entry.value_ptr.*);
                }
            }

            // Allocate and copy the module name into our allocator.
            const name_len = modName.len;
            var name_buf = try self.allocator.alloc(u8, name_len);
            std.mem.copyForwards(u8, name_buf, modName);
            const name_slice = name_buf[0..name_len];

            try modules_map.put(name_slice, moduleInfo);

            // TODO this is also a winapi macro
            if (win.kernel32.Module32Next(snapshot, &module_entry) == 0) break;
        }

        self.mod_map = modules_map;
        return;
    }

    pub fn get_current_mod(self: *Self) void {
        const modinfo = self.map_address_to_mod(@intFromPtr(&get_current_mod)).?;
        self.current_mod = modinfo.baseAddr;
    }

    fn load_initial_exe(self: *Self) !void {
        // Check that the module exists in our modules map.
        var map_iterator = self.mod_map.iterator();
        var mod_name: []const u8 = undefined;
        var base_addr: usize = undefined;
        while (map_iterator.next()) |entry| {
            mod_name = entry.key_ptr.*;
            if (entry.value_ptr.*.baseAddr == self.current_mod) {
                base_addr = entry.value_ptr.*.baseAddr;
                break;
            }
        }
        var mod_name_full: [256]u16 = undefined;
        const mod_name_return: []u16 = @ptrCast(try win.GetModuleFileNameW(null, &mod_name_full, 256));
        const mod_name_full_u8: []u8 = try std.unicode.utf16LeToUtf8Alloc(self.allocator, mod_name_return);
        defer self.allocator.free(mod_name_full_u8);
        // Here we assume that the module name is also the filename in the current directory.
        // Adjust this as needed if your modules are in a different location.
        const fs = std.fs.cwd();
        var file = try fs.openFile(mod_name_full_u8, .{});
        const file_stat = try file.stat();
        const file_size = file_stat.size;
        const buffer = try self.allocator.alloc(u8, file_size);
        _ = try file.readAll(buffer);
        file.close();
        self.exe_buf = buffer;
        try self.fix_rva(self.exe_buf, base_addr);
        return;
    }

    fn fix_rva(self: *Self, buffer: []u8, base_addr: usize) !void {
        if (buffer.len < @sizeOf(winc.IMAGE_DOS_HEADER)) {
            return warder_error.InvalidBuffer;
        }
        // Cast the beginning of the buffer as a DOS header.
        const dosHeader: *winc.IMAGE_DOS_HEADER = @ptrCast(@alignCast(buffer.ptr));
        if (dosHeader.e_magic != winc.IMAGE_DOS_SIGNATURE) {
            return warder_error.InvalidDOSHeader;
        }
        const nt_header_offset: usize = @intCast(dosHeader.e_lfanew);
        if (buffer.len < nt_header_offset + @sizeOf(winc.IMAGE_NT_HEADERS)) {
            return warder_error.InvalidBuffer;
        }
        // Obtain a pointer to the NT headers.
        const nt_headers: *winc.IMAGE_NT_HEADERS = @ptrCast(@alignCast(buffer.ptr + nt_header_offset));
        if (nt_headers.Signature != winc.IMAGE_NT_SIGNATURE) {
            return warder_error.InvalidNTSignature;
        }

        const offset = base_addr - nt_headers.OptionalHeader.ImageBase;
        const relocations =
            nt_headers.OptionalHeader.DataDirectory[winc.IMAGE_DIRECTORY_ENTRY_BASERELOC];
        const optHeaderSize = nt_headers.FileHeader.SizeOfOptionalHeader;
        const sections_ptr: *align(1) winc.IMAGE_SECTION_HEADER =
            (@ptrCast((@as([*]u8, @ptrCast(@constCast(&nt_headers.OptionalHeader)))) + optHeaderSize));
        // Create a slice over the section headers.
        const numSections = nt_headers.FileHeader.NumberOfSections;
        const sections: [*]align(1) winc.IMAGE_SECTION_HEADER = @ptrCast(sections_ptr);
        var raw_reloc_ptr: [*]u8 = undefined;
        self.sections = try self.allocator.alloc(MappedMockSection, numSections);

        for (sections[0..numSections], 0..) |section, i| {
            const cast_name = @as([*:0]u8, @ptrCast(@constCast(&sections[i].Name)));
            const section_name_trimmed = cast_name[0..std.mem.len(cast_name)];
            self.sections[i] =
                MappedMockSection{
                    .virtual_address = section.VirtualAddress,
                    .name = section_name_trimmed,
                    .size = section.SizeOfRawData,
                    .ptr = buffer[section.PointerToRawData..].ptr,
                };

            if (std.mem.eql(u8, section_name_trimmed, ".reloc")) {
                raw_reloc_ptr = buffer[section.PointerToRawData..].ptr;
            }
        }

        const relocation_table: [*]u8 = raw_reloc_ptr;
        var relocations_processed: u32 = 0;

        while (relocations_processed < relocations.Size) {
            const relocation_block: *align(1) BASE_RELOCATION_BLOCK =
                @ptrCast(@alignCast(relocation_table[relocations_processed..]));
            relocations_processed += @sizeOf(BASE_RELOCATION_BLOCK);
            const relocations_count =
                (relocation_block.BlockSize - @sizeOf(BASE_RELOCATION_BLOCK)) / @sizeOf(BASE_RELOCATION_ENTRY);
            const relocation_entries: [*]align(1) BASE_RELOCATION_ENTRY =
                @ptrCast(@alignCast(relocation_table[relocations_processed..]));

            for (0..relocations_count) |entry_index| {
                if (relocation_entries[entry_index].Type != 0) {
                    const relocation_rva: usize =
                        relocation_block.PageAddress + relocation_entries[entry_index].Offset;
                    var section_pointer: [*]u8 = undefined;
                    var section_offset_virtual: usize = undefined;
                    for (0..self.sections.len) |i| {
                        const section: MappedMockSection = self.sections[i];
                        if (relocation_rva >= section.virtual_address and
                            relocation_rva <= (section.virtual_address + section.size))
                        {
                            section_pointer = section.ptr;
                            section_offset_virtual = section.virtual_address;
                            break;
                        }
                    }
                    const ptr: *align(1) usize =
                        @ptrCast(section_pointer[relocation_rva - section_offset_virtual ..]);
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
    // fix_iat
    //
    //
    // map_address_to_mod
    // map_address_to_page
    // map_page_to_mod
    //
    /// Given an absolute address, find the module (ModuleInfo) that contains it.
    pub fn map_address_to_mod(self: *Self, address: usize) ?ModuleInfo {
        var mod_iter = self.mod_map.iterator();
        while (mod_iter.next()) |entry| {
            const mod_info = entry.value_ptr.*;
            if (address >= mod_info.baseAddr and address < mod_info.baseAddr + mod_info.size) {
                return mod_info;
            }
        }
        return null;
    }

    /// Given an absolute address, find the page (PageInfo) that contains it.
    pub fn map_address_to_page(self: *Self, address: usize) ?*PageInfo {
        var page_iter = self.page_map.iterator();
        while (page_iter.next()) |entry| {
            const page = entry.value_ptr.*;
            if (address >= page.baseAddr and address < page.baseAddr + page.regionSize) {
                return page;
            }
        }
        return null;
    }

    /// Given a PageInfo, find the module (ModuleInfo) that contains that page.
    pub fn map_page_to_mod(self: *Self, page: PageInfo) ?ModuleInfo {
        // Here we use the page's base address to determine the module that contains it.
        var mod_iter = self.mod_map.iterator();
        while (mod_iter.next()) |entry| {
            const mod_info = entry.value_ptr.*;
            if (page.baseAddr >= mod_info.baseAddr and
                page.baseAddr < mod_info.baseAddr + mod_info.size)
            {
                return mod_info;
            }
        }
        return null;
    }

    pub fn check_exe_sections(self: *Self) !void {
        // 1) Find the .exe entry from our mod_map.
        var exe_module: ModuleInfo = undefined;

        var key_iter = self.mod_map.iterator();
        while (key_iter.next()) |entry| {
            if (entry.value_ptr.*.baseAddr == self.current_mod) {
                exe_module = entry.value_ptr.*;
                break;
            }
        }

        // The base address of the loaded .exe in memory
        const base_addr_usize = exe_module.baseAddr;
        const base_addr_ptr: ?*const u8 = @ptrFromInt(base_addr_usize);

        // 2) Parse the DOS header from the loaded memory
        if (@sizeOf(winc.IMAGE_DOS_HEADER) > 0 and base_addr_ptr == null) {
            return error.InvalidModuleBase;
        }
        const dos_header: *const winc.IMAGE_DOS_HEADER = @ptrCast(@alignCast(base_addr_ptr.?));
        if (dos_header.e_magic != winc.IMAGE_DOS_SIGNATURE) {
            return error.InvalidDOSHeader;
        }

        // 3) Parse the NT headers
        const nt_header_offset: usize = @intCast(dos_header.e_lfanew);
        const nt_headers: *const winc.IMAGE_NT_HEADERS =
            @ptrFromInt(@intFromPtr(base_addr_ptr.?) + nt_header_offset);
        if (nt_headers.Signature != winc.IMAGE_NT_SIGNATURE) {
            return error.InvalidNTSignature;
        }

        // 4) Get the first section header. This is right after the OptionalHeader.
        const file_header = nt_headers.FileHeader;
        const optional_header_size: usize = @intCast(file_header.SizeOfOptionalHeader);

        // Points to the first IMAGE_SECTION_HEADER in memory
        const first_section_header: [*]const winc.IMAGE_SECTION_HEADER =
            @ptrFromInt(@intFromPtr(&nt_headers.OptionalHeader) + optional_header_size);

        // Number of sections as reported by the PE file
        const section_count = file_header.NumberOfSections;

        if (section_count == 0) {
            // No sections to check
            return;
        }

        // 5) Compare each loaded section to the corresponding bytes in self.exe_buf
        //    (which should contain the on-disk copy of the executable).
        for (0..section_count) |sec_index| {
            const sec_header = first_section_header[sec_index];

            // If the section has no raw data, skip
            if (sec_header.SizeOfRawData == 0) continue;
            if (!std.mem.eql(u8, sec_header.Name[0..5], ".text")) {
                continue;
            }

            // The memory range for this section in the running process
            const loaded_sec_start_ptr: [*]u8 =
                @ptrFromInt(@intFromPtr(base_addr_ptr.?) + sec_header.VirtualAddress);
            const loaded_sec_slice = loaded_sec_start_ptr[0..sec_header.SizeOfRawData];

            // The on-disk section bytes in self.exe_buf (already read from file).
            // Make sure we don’t go out of bounds on exe_buf in case of malformed sections.
            const raw_start = sec_header.PointerToRawData;
            const raw_size = sec_header.SizeOfRawData;
            if (raw_start + raw_size > self.exe_buf.len) {
                return error.InvalidSectionSize;
            }
            const disk_sec_slice = self.exe_buf[raw_start .. raw_start + raw_size];

            // Compare them directly. If they differ, it means the loaded section
            // has been modified or patched since loading.
            if (!std.mem.eql(u8, loaded_sec_slice, disk_sec_slice)) {
                return error.SectionMismatch;
            }
        }

        return;
    }

    pub fn register_call(self: *Self, callbuf: *const anyopaque) !void {
        try self.callbuff.append(self.allocator, callbuf);
        //protection logic

    }
    pub fn deregister_call(self: *Self, callbuf: *const anyopaque) void {
        const ptr = self.callbuff.pop();
        if (ptr != callbuf) {}
        //protection logic
    }

    fn change_page_protection(self: *Self, page: *PageInfo, protection: u32) !bool {
        // var obj: OBJECT_ATTRIBUTES = undefined;
        // InitializeObjectAttributes(
        //     &obj,
        //     null,
        //     0,
        //     null,
        //     null,
        // );
        // var clientId: ClientId = undefined;
        // clientId.UniqueProcess = GetCurrentProcessId();
        // clientId.UniqueThread = 0;
        // var process_handle: usize = undefined;
        // const ProcessHandle = try self.syscall_manager.NtOpenProcess(
        //     &process_handle,
        //     winc.PROCESS_ALL_ACCESS,
        //     &obj,
        //     &clientId,
        // );
        var old_access: usize = 0;
        var numberOfByteToProtect: usize = 0x1000;
        const ret_val = try self.syscall_manager.invoke(.NtVirtualProtectMemory, .{
            0xFFFFFFFFFFFFFFFF,
            &page.baseAddr,
            &numberOfByteToProtect,
            protection,
            &old_access,
        });
        page.access = protection;
        if (NT_SUCCESS(@intCast(ret_val))) {
            return true;
        } else {
            return false;
        }
    }
    pub fn protect_page(self: *Self, page: *PageInfo) !bool {
        if (page.baseAddr == self.ntdll_special_page) {
            return false;
        }
        const new_protection = stripExecutionProtection(page.unprotected_access);
        if (new_protection != page.access) {
            return try self.change_page_protection(
                page,
                new_protection,
            );
        }
        return false;
    }
    pub fn unprotect_page(self: *Self, page: *PageInfo) !bool {
        if (page.baseAddr == self.ntdll_special_page) {
            return false;
        }
        return try self.change_page_protection(
            page,
            page.unprotected_access,
        );
    }

    pub fn protect_global(self: *Self) !void {
        var hash_iterator = self.mod_map.iterator();
        while (hash_iterator.next()) |entry| {
            if (entry.value_ptr.*.baseAddr == self.current_mod) {
                continue;
            }

            for (entry.value_ptr.*.pages.items) |page| {

                // well... the constCast is an interesting choice
                _ = try self.protect_page(page);
            }
        }
    }
    pub fn unprotect_global(self: *Self) !void {
        var hash_iterator = self.mod_map.iterator();
        while (hash_iterator.next()) |entry| {
            const key_len = entry.key_ptr.*.len;
            if (std.mem.eql(u8, entry.key_ptr.*[key_len - 4 .. key_len], ".exe")) {
                continue;
            }

            for (entry.value_ptr.*.pages.items) |page| {

                // well... the constCast is an interesting choice
                _ = try self.unprotect_page(page);
            }
        }
    }

    pub fn patch_ntdll(self: *Self) !void {
        var payload: [0x11]u8 = .{
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x0F, 0x05,
            0xC3,
        };

        const ptr_to_addr: *align(1) usize = @ptrCast(@as([*]u8, @ptrCast(&payload))[6..]);
        ptr_to_addr.* = @intFromPtr(&_MEH_warden_asm);
        // const syscall_ptr: [*]u8 = @ptrCast(@as([*]u8, @ptrCast(&payload))[14..]);
        const ntdll = win.kernel32.GetModuleHandleW(W("ntdll.dll")).?;

        const ntkued: [*]u8 = @ptrCast(win.kernel32.GetProcAddress(ntdll, "KiUserExceptionDispatcher").?);
        const page = self.map_address_to_page(@intFromPtr(ntkued)).?;
        self.ntdll_special_page = page.baseAddr;
        _ = try self.change_page_protection(page, win.PAGE_READWRITE);
        std.mem.copyForwards(u8, self.ntdll_buffer[0..0x11], ntkued[0..0x11]);
        std.mem.copyForwards(u8, ntkued[0..0x11], payload[0..0x11]);

        _ = try self.change_page_protection(page, win.PAGE_EXECUTE_READ);
    }
    pub fn unpatch_ntdll(self: *Self) !void {
        const ntdll = win.kernel32.GetModuleHandleW(W("ntdll.dll")).?;
        const ntkued: [*]u8 = @ptrCast(win.kernel32.GetProcAddress(ntdll, "KiUserExceptionDispatcher").?);
        const page = self.map_address_to_page(@intFromPtr(ntkued)).?;
        self.ntdll_special_page = page.baseAddr;
        _ = try self.change_page_protection(page, win.PAGE_READWRITE);
        std.mem.copyForwards(u8, ntkued[0..0x11], self.ntdll_buffer[0..0x11]);
        _ = try self.change_page_protection(page, win.PAGE_EXECUTE_READ);
    }
};
pub fn stripExecutionProtection(protect: u32) u32 {
    // Assume the lower 8 bits represent the basic protection type.
    const basic = protect & 0xFF;
    // Preserve any modifiers (flags above the lower 8 bits).
    const mask: u8 = 0xFF;
    const modifiers = protect & ~mask;
    const newBasic: u32 = switch (basic) {
        win.PAGE_EXECUTE => win.PAGE_READONLY,
        win.PAGE_EXECUTE_READ => win.PAGE_READONLY,
        win.PAGE_EXECUTE_READWRITE => win.PAGE_READWRITE,
        win.PAGE_EXECUTE_WRITECOPY => win.PAGE_WRITECOPY,
        else => basic,
    };
    return newBasic | modifiers;
}
fn NT_SUCCESS(_status: usize) bool {
    const status: u32 = @intCast(_status & 0xFF_FF_FF_FF);

    return (status > 0 and status < 0x3FFFFFFF) or
        (status > 0x40000000 and status < 0x7FFFFFFF);
}

fn is_page_executable(access: u32) bool {
    // These are example Windows page protection constants.
    // Adjust them if your definitions differ.
    return access == win.PAGE_EXECUTE or access == win.PAGE_EXECUTE_READ or
        access == win.PAGE_EXECUTE_READWRITE or access == win.PAGE_EXECUTE_WRITECOPY;
}
const OBJECT_ATTRIBUTES = struct {
    Length: usize,
    RootDirectory: ?*anyopaque,
    ObjectName: ?*win.UNICODE_STRING,
    Attributes: usize,
    SecurityDescriptor: ?*anyopaque,
    SecurityQualityOfService: ?*anyopaque,
};
fn InitializeObjectAttributes(
    attrs: *OBJECT_ATTRIBUTES,
    name: ?*win.UNICODE_STRING,
    attributes: u32,
    rootDir: ?*anyopaque,
    securityDescriptor: ?*anyopaque,
) void {
    attrs.Length = @sizeOf(win.OBJECT_ATTRIBUTES);
    attrs.RootDirectory = rootDir;
    attrs.ObjectName = name;
    attrs.Attributes = attributes;
    attrs.SecurityDescriptor = securityDescriptor;
    attrs.SecurityQualityOfService = null;
}
pub fn createUnicodeString(allocator: *std.mem.Allocator, s: []const u8) !win.UNICODE_STRING {
    // Convert and allocate a null-terminated UTF-16 LE version of the input.
    const wide = try Walloc(allocator, s);
    // `wide` is a slice of u16 including the terminating 0.
    // Calculate the length in bytes excluding the null terminator.
    const count = wide.len - 1;
    return win.UNICODE_STRING{
        .Length = @intCast(count * 2),
        .MaximumLength = @intCast(wide.len * 2),
        .Buffer = wide.ptr, // Get pointer to the first u16 element.
    };
}

fn GetCurrentProcessId() usize {
    // fun fact, mov eax, <anything> clears high 32 bits of rax
    //0:  65 48 8b 04 25 30 00    mov    rax,QWORD PTR gs:0x30
    //7:  00 00
    //9:  8b 40 40                mov    eax,DWORD PTR [rax+0x40]
    return asm volatile (".byte 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x40 \n"
        : [ret] "={rax}" (-> usize),
        :
        : .{ .rax = true });
}
