const std = @import("std");

// Declaratively construct a build graph executed by Zig's build runner.
pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const syscall_dep = b.dependency("syscall_manager", .{});
    const syscall_module = syscall_dep.module("syscall_manager");

    const syslogger_dep = b.dependency("sys_logger", .{});
    const syslogger_module = syslogger_dep.module("sys_logger");

    // Allow overriding NASM from the command line:
    //   zig build -Dnasm="C:\\path\\to\\nasm.exe"
    const nasm_bin = b.option([]const u8, "nasm", "Path to nasm executable") orelse "nasm";

    // ---- NASM steps (these are real build steps now) ----
    // warden.asm -> warden_asm.o
    const warden_asm_cmd = b.addSystemCommand(&.{ nasm_bin, "-f", "win64" });
    warden_asm_cmd.addFileArg(b.path("src/warden.asm"));
    warden_asm_cmd.addArg("-o");
    const warden_obj = warden_asm_cmd.addOutputFileArg("warden_asm.o");

    // state_manager.asm -> state_manager.o
    const state_asm_cmd = b.addSystemCommand(&.{ nasm_bin, "-f", "win64" });
    state_asm_cmd.addFileArg(b.path("src/state_manager.asm"));
    state_asm_cmd.addArg("-o");
    const state_obj = state_asm_cmd.addOutputFileArg("state_manager.o");

    // Optional: a named step you can run explicitly: `zig build asm`
    const asm_step = b.step("asm", "Assemble NASM sources");
    asm_step.dependOn(&warden_asm_cmd.step);
    asm_step.dependOn(&state_asm_cmd.step);

    // ---- Main executable ----
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const hookguard_module = b.addModule("hookguard", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("syscall_manager", syscall_module);
    exe_mod.addImport("sys_logger", syslogger_module);

    hookguard_module.addImport("syscall_manager", syscall_module);
    hookguard_module.addImport("sys_logger", syslogger_module);

    const exe = b.addExecutable(.{
        .name = "hookguard",
        .root_module = exe_mod,
    });

    // Wire generated objects into the link step (these LazyPaths carry deps)
    exe.addObjectFile(state_obj);
    exe.addObjectFile(warden_obj);

    // If you want to be explicit, keep this (harmless; ensures ordering):
    exe.step.dependOn(asm_step);

    b.installArtifact(exe);

    // ---- Run step ----
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // ---- Test discovery + run ----
    const test_step = b.step("test", "Run all tests in ./src matching *test.zig");

    const tests_dir = std.fs.cwd().openDir("src", .{ .iterate = true }) catch {
        @panic("NO src DIR");
    };
    var it = tests_dir.iterate();

    while (it.next() catch @panic("NO TESTS")) |entry| {
        if (std.mem.endsWith(u8, entry.name, "test.zig")) {
            const exe_name = entry.name[0 .. entry.name.len - 4];

            const source_rel = std.mem.concat(
                std.heap.page_allocator,
                u8,
                &[_][]const u8{ "src/", entry.name },
            ) catch @panic("OOM");

            const test_exe_mod = b.createModule(.{
                .root_source_file = b.path(source_rel),
                .target = target,
                .optimize = optimize,
            });
            test_exe_mod.addImport("syscall_manager", syscall_module);
            test_exe_mod.addImport("sys_logger", syslogger_module);
            test_exe_mod.addImport("hookguard", hookguard_module);

            const test_exe = b.addExecutable(.{
                .name = exe_name,
                .root_module = test_exe_mod,
            });

            // Reuse the same generated object outputs; the deps are preserved.
            test_exe.addObjectFile(state_obj);
            test_exe.addObjectFile(warden_obj);

            // Explicitly depend on assembly step (optional but clear)
            test_exe.step.dependOn(asm_step);

            const test_run = b.addRunArtifact(test_exe);
            test_run.step.dependOn(&test_exe.step);

            test_step.dependOn(&test_run.step);
        }
    }
}
