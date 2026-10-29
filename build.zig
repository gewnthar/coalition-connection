const std = @import("std");

// Steps:
//   zig build                 build everything (zig build --release builds ReleaseSafe)
//   zig build test            unit tests in src/, plus the startup-trip harness
//   zig build fuzz -Dseed=N   seeded fuzz run (fuzz/main.zig)
//   zig build sim -Dseed=N    seeded deterministic simulation run (sim/main.zig)

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });
    const seed = b.option(u64, "seed", "Seed for the fuzz and simulation runs") orelse 0x5eed;

    const root = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{ .root_module = root });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests and the startup-trip harness");
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
        // Test harnesses: built and run by their own steps, never installed with the program.
        const exe = b.addExecutable(.{ .name = runner.name, .root_module = module });
        const run = b.addRunArtifact(exe);
        const step = b.step(runner.name, runner.description);
        step.dependOn(&run.step);
    }

    // Startup-trip harness (sim/startup_trip.zig): a tripped assertion ends the process,
    // so each case is its own build, run as a child process by `zig build test`, and must
    // exit with the code its case expects. Always ReleaseSafe, the production mode: the
    // guard is an assertion, compiled out where assertions are off. Never installed.
    const trip_root = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    std.debug.assert(trip.cases.len <= trip.cases_max);
    for (trip.cases, 0..) |trip_case, index| {
        const trip_options = b.addOptions();
        trip_options.addOption(u32, "case_index", @intCast(index));
        const module = b.createModule(.{
            .root_source_file = b.path("sim/startup_trip.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .imports = &.{
                .{ .name = "coalition_connection", .module = trip_root },
                .{ .name = "build_options", .module = trip_options.createModule() },
            },
        });
        const exe = b.addExecutable(.{ .name = b.fmt("startup_trip_{s}", .{trip_case.name}), .root_module = module });
        const run = b.addRunArtifact(exe);
        run.expectExitCode(trip.expectedExit(trip_case));
        test_step.dependOn(&run.step);
    }
}

const trip = @import("sim/startup_trip_cases.zig");

const Runner = struct {
    name: []const u8,
    path: []const u8,
    description: []const u8,
};
