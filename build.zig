const std = @import("std");

// Steps:
//   zig build                 build everything (use --release=safe for production builds)
//   zig build test            unit tests in src/
//   zig build fuzz -Dseed=N   seeded fuzz run (fuzz/main.zig)
//   zig build sim -Dseed=N    seeded deterministic simulation run (sim/main.zig)

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const seed = b.option(u64, "seed", "Seed for the fuzz and simulation runs") orelse 0x5eed;

    const root = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{ .root_module = root });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    const options = b.addOptions();
    options.addOption(u64, "seed", seed);
    const options_module = options.createModule();

    const runners = [_]Runner{
        .{ .name = "fuzz", .path = "fuzz/main.zig", .description = "Run the seeded fuzzer" },
        .{ .name = "sim", .path = "sim/main.zig", .description = "Run a seeded simulation" },
    };
    for (runners) |runner| {
        const module = b.createModule(.{
            .root_source_file = b.path(runner.path),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "coalition_connection", .module = root },
                .{ .name = "build_options", .module = options_module },
            },
        });
        const exe = b.addExecutable(.{ .name = runner.name, .root_module = module });
        b.installArtifact(exe);

        const run = b.addRunArtifact(exe);
        const step = b.step(runner.name, runner.description);
        step.dependOn(&run.step);
    }
}

const Runner = struct {
    name: []const u8,
    path: []const u8,
    description: []const u8,
};
