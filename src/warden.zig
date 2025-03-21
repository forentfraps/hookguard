const std = @import("std");
const syscall_lib = @import("syscall_wrapper.zig");
const winc = @import("Windows.h.zig");
const win = std.os.windows;
const state_manager = @import("state_manager.zig");
const syscall_manager_lib = @import("syscall_manager.zig");

const syscall = syscall_lib.syscall;
const syscall_manager = syscall_manager_lib.SyscallManager;
const W = std.unicode.utf8ToUtf16LeStringLiteral;

extern fn retry_asm(*const anyopaque) void;

pub var global_warden: ?*warden = null;

pub fn set_global_warden(w: *warden) void {
    global_warden = w;
}

const warder_error = error{
    SnapshotFail,
    Module32FirstFail,
    InvalidBuffer,
    InvalidDOSHeader,
    InvalidNTSignature,
};

pub fn VEH_warden(exception: *win.EXCEPTION_POINTERS) callconv(.c) c_long {
    const exception_record = exception.ExceptionRecord;
    const context = exception.ContextRecord;
    std.debug.print(
        "excpetion: {x} at {x}\n",
        .{ exception_record.ExceptionCode, exception_record.ExceptionAddress },
    );
    std.debug.print(
        "died at module: {any}\n",
        .{global_warden.?.map_address_to_mod(context.Rip).?},
    );
    std.debug.print("checking the integrity\n", .{});
    if (exception_record.ExceptionCode == 0xc0000005) {
        return win.EXCEPTION_CONTINUE_SEARCH;
    }
    global_warden.?.check_exe_sections() catch {
        std.debug.print("FAILED at verifying\n", .{});
    };
    std.debug.print("supposedly nothing bad was found replaying\n", .{});
    retry_asm(global_warden.?.callbuff.items[global_warden.?.callbuff.items.len - 1]);

    return win.EXCEPTION_CONTINUE_SEARCH;
}
pub const PageInfo = struct {
    baseAddr: usize,
    regionSize: usize,
    access: u32,
    unprotected_access: u32,
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

    exe_buf: []u8 = undefined,
    sections: []MappedMockSection = undefined,

    syscall_manager: syscall_manager = undefined,

    callbuff: std.ArrayList(*const anyopaque) = undefined,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        var self = Self{ .allocator = allocator };
        _ = try self.enumerate_memory();
        _ = try self.enumerate_modules();
        _ = try self.load_initial_exe();
        self.callbuff = std.ArrayList(*const anyopaque).init(allocator);
        self.syscall_manager = syscall_manager{};

        self.init_complete = true;
        return self;
    }

    fn enumerate_memory(self: *Self) !void {
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
                    .unprotected_access = mbi.Protect,
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
    fn load_initial_exe(self: *Self) !void {
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
        self.exe_buf = buffer;
        try self.fix_rva(self.exe_buf, base_addr);
        return;
    }

    fn fix_rva(self: *Self, buffer: []u8, base_addr: usize) !void {
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
        const relocations =
            nt_headers.OptionalHeader.DataDirectory[winc.IMAGE_DIRECTORY_ENTRY_BASERELOC];
        const optHeaderSize = nt_headers.FileHeader.SizeOfOptionalHeader;
        const sections_ptr: *align(1) winc.IMAGE_SECTION_HEADER =
            (@ptrCast((@as([*]u8, @constCast(@ptrCast(&nt_headers.OptionalHeader)))) + optHeaderSize));
        // Create a slice over the section headers.
        const numSections = nt_headers.FileHeader.NumberOfSections;
        const sections: [*]align(1) winc.IMAGE_SECTION_HEADER = @ptrCast(sections_ptr);
        var raw_reloc_ptr: [*]u8 = undefined;
        self.sections = try self.allocator.alloc(MappedMockSection, numSections);

        for (sections[0..numSections], 0..) |section, i| {
            const cast_name = @as([*:0]u8, @constCast(@ptrCast(&sections[i].Name)));
            const section_name_trimmed = cast_name[0..std.mem.len(cast_name)];
            self.sections[i] =
                MappedMockSection{
                    .virtual_address = section.VirtualAddress,
                    .name = section_name_trimmed,
                    .size = section.SizeOfRawData,
                    .ptr = buffer[section.PointerToRawData..].ptr,
                };

            // std.debug.print("{*} == {*}\n", .{ &(section.Name), section_name_trimmed });
            if (std.mem.eql(u8, section_name_trimmed, ".reloc")) {
                raw_reloc_ptr = buffer[section.PointerToRawData..].ptr;
                // std.debug.print("raw_reloc_ptr {*}\n", .{raw_reloc_ptr});
            }
        }

        const relocation_table: [*]u8 = raw_reloc_ptr;
        var relocations_processed: u32 = 0;
        // std.debug.print("virt addr of reloca table: {*}\n", .{relocation_table});

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
                    // std.debug.print("address to fix is {x} off the base\n", .{relocation_rva});
                    //log.info("Value before rva is {x} changing to {*}\n", .{ ptr.*, ptr });
                    var section_pointer: [*]u8 = undefined;
                    var section_offset_virtual: usize = undefined;
                    for (0..self.sections.len) |i| {
                        const section: MappedMockSection = self.sections[i];
                        if (relocation_rva >= section.virtual_address and
                            relocation_rva <= (section.virtual_address + section.size))
                        {
                            section_pointer = section.ptr;
                            section_offset_virtual = section.virtual_address;
                            // std.debug.print("Section rva {s}\n", .{section.name});
                            break;
                        }
                    }
                    const ptr: *align(1) usize =
                        @ptrCast(section_pointer[relocation_rva - section_offset_virtual ..]);
                    // std.debug.print("{*} - {x}\n", .{ ptr, ptr.* });
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
    pub fn map_address_to_page(self: *Self, address: usize) ?PageInfo {
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
        var exe_key: []const u8 = undefined;
        var exe_module: ModuleInfo = undefined;

        var key_iter = self.mod_map.keyIterator();
        while (key_iter.next()) |key| {
            if (std.mem.eql(u8, key.*[key.*.len - 4 ..], ".exe")) {
                exe_key = key.*;
                exe_module = self.mod_map.get(key.*) orelse continue;
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
        const dos_header: *const winc.IMAGE_DOS_HEADER = @alignCast(@ptrCast(base_addr_ptr.?));
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
            std.debug.print("Section index: {d}\n", .{sec_index});
            if (sec_header.SizeOfRawData == 0) continue;
            if (!std.mem.eql(u8, sec_header.Name[0..5], ".text")) {
                std.debug.print("skipping not text: {s}\n", .{sec_header.Name});
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
                std.debug.print("bad section \n", .{});
                return error.SectionMismatch;
            }
        }

        // If we reach here, all sections matched exactly.
        // You can return success or print a message as needed.
        return;
    }

    pub fn register_call(self: *Self, callbuf: *const anyopaque) !void {
        try self.callbuff.append(callbuf);
        //protection logic

    }
    pub fn deregister_call(self: *Self, callbuf: *const anyopaque) void {
        const ptr = self.callbuff.pop();
        if (ptr != callbuf) {
            std.debug.print("tragic... Ptrs did not match during call deregistering\n", .{});
        }
        //protection logic
    }

    fn change_page_protection(self: *Self, base_addr: usize, protection: u32) !bool {
        var page: PageInfo = try self.page_map.get(base_addr);

        var obj: win.OBJECT_ATTRIBUTES = undefined;
        InitializeObjectAttributes(
            &obj,
            null,
            0,
            null,
            null,
        );
        var clientId: win.CLIENT_ID = undefined;
        clientId.UniqueProcess = GetCurrentProcessId();
        clientId.UniqueThread = 0;
        var process_handle: usize = undefined;
        const ProcessHandle = try self.syscall_manager.NtOpenProcess(
            &process_handle,
            winc.PROCESS_ALL_ACCESS,
            &obj,
            &clientId,
        );
        var old_access: usize = 0;
        const ret_val = try self.syscall_manager.NtVirtualProtectMemory(
            ProcessHandle,
            page.baseAddr,
            page.regionSize,
            protection,
            &old_access,
        );
        if (NT_SUCCESS(ret_val)) {
            page.access = protection;
            return true;
        } else {
            return false;
        }
    }
    pub fn protect_page(self: *Self, base_addr: usize) !bool{
        var page: PageInfo = try self.page_map.get(base_addr);
        return self.change_page_protection(base_addr, win.)
    }

    pub fn protect_global(self: *Self) bool{

    }

    //
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

fn NT_SUCCESS(status: winc.NTSTATUS) bool {
    return (status > 0 and status < 0x3FFFFFFF) or
        (status > 0x40000000 and status < 0x7FFFFFFF);
}

fn is_page_executable(access: u32) bool {
    // These are example Windows page protection constants.
    // Adjust them if your definitions differ.
    const PAGE_EXECUTE = 0x10;
    const PAGE_EXECUTE_READ = 0x20;
    const PAGE_EXECUTE_READWRITE = 0x40;
    const PAGE_EXECUTE_WRITECOPY = 0x80;
    return access == PAGE_EXECUTE or access == PAGE_EXECUTE_READ or
        access == PAGE_EXECUTE_READWRITE or access == PAGE_EXECUTE_WRITECOPY;
}
fn InitializeObjectAttributes(
    attrs: *win.OBJECT_ATTRIBUTES,
    name: ?*u8,
    attributes: u32,
    rootDir: ?*void,
    securityDescriptor: ?*void,
) void {
    attrs.Length = @sizeOf(win.OBJECT_ATTRIBUTES);
    attrs.RootDirectory = rootDir;
    attrs.ObjectName = name;
    attrs.Attributes = attributes;
    attrs.SecurityDescriptor = securityDescriptor;
    attrs.SecurityQualityOfService = null;
}

fn GetCurrentProcessId() u32 {
    return asm volatile ("mov rax, gs:30h\nmov eax, [rax + 0x40]\n"
        : [ret] "={rax}" (-> usize),
        :
        : "rax"
    );
}
