const std = @import("std");
const assert = std.debug.assert;

// Steps:
//   zig build                 build and install the server. Release builds are always safe
//                             (ReleaseSafe): --release, --release=safe, =fast and =small all
//                             build safe. The server is Linux only, so a build for another
//                             operating system stops with a compile error.
//   zig build test            unit tests in src/, the server's tests and version check, plus
//                             the startup-trip harness
//   zig build fuzz -Dseed=N   seeded fuzz run (fuzz/main.zig)
//   zig build sim -Dseed=N    seeded deterministic simulation run (sim/main.zig)

const package = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .safe });
    const seed = b.option(u64, "seed", "Seed for the fuzz and simulation runs") orelse 0x5eed;

    const root = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Only Debug and safe exist: the preferred mode turns every --release into safe.
    assert(optimize == .debug or optimize == .safe);

    const tests = b.addTest(.{ .root_module = root });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests, the version check and the startup-trip harness");
    test_step.dependOn(&run_tests.step);

    addServer(b, root, target, optimize, test_step);
    addRunners(b, root, target, optimize, seed);
    addStartupTrip(b, target, test_step);
    // The unit tests, the server's tests and version check, and one run per trip case.
    assert(test_step.dependencies.items.len == 3 + trip.cases.len);
}

/// The server program, installed by the default step. `zig build test` runs its tests, then
/// runs it once and checks its version line.
fn addServer(
    b: *std.Build,
    root: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    test_step: *std.Build.Step,
) void {
    // The version is a semantic version; a malformed one stops the build here.
    const version = std.SemanticVersion.parse(package.version) catch |err| {
        std.debug.panic("build.zig.zon: version {s} is not a semantic version: {t}", .{ package.version, err });
    };
    assert(version.major < 1000 and version.minor < 1000);
    assert(std.mem.eql(u8, package.minimum_zig_version, "0.17.0"));
    const dependencies_before = test_step.dependencies.items.len;
    const options = b.addOptions();
    options.addOption([]const u8, "version", package.version);
    const module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "coalition_connection", .module = root },
            .{ .name = "build_options", .module = options.createModule() },
        },
    });
    const exe = b.addExecutable(.{ .name = "coalition-connection", .root_module = module });
    b.installArtifact(exe);

    const run_tests = b.addRunArtifact(b.addTest(.{ .root_module = module }));
    test_step.dependOn(&run_tests.step);
    const run = b.addRunArtifact(exe);
    run.expectStdOutEqual("coalition-connection " ++ package.version ++ "\n");
    run.expectExitCode(0);
    // The version check runs after the tests, so a failing write shows up as a test first.
    run.step.dependOn(&run_tests.step);
    test_step.dependOn(&run.step);
    assert(test_step.dependencies.items.len == dependencies_before + 2);
}

const Runner = struct {
    name: []const u8,
    path: []const u8,
    description: []const u8,
};

/// The seeded fuzz and simulation runs. Test harnesses: built and run by their own steps,
/// never installed with the program.
fn addRunners(
    b: *std.Build,
    root: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    seed: u64,
) void {
    const runners = [_]Runner{
        .{ .name = "fuzz", .path = "fuzz/main.zig", .description = "Run the seeded fuzzer" },
        .{ .name = "sim", .path = "sim/main.zig", .description = "Run a seeded simulation" },
    };
    const steps_before = b.top_level_steps.count();
    assert(root.root_source_file != null);
    const options = b.addOptions();
    options.addOption(u64, "seed", seed);
    const options_module = options.createModule();
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
        const run = b.addRunArtifact(exe);
        const step = b.step(runner.name, runner.description);
        step.dependOn(&run.step);
    }
    assert(b.top_level_steps.count() == steps_before + runners.len);
}

/// Startup-trip harness (sim/startup_trip.zig): a tripped assertion ends the process, so
/// each case is its own build, run as a child process by `zig build test`, and must exit
/// with the code its case expects. Always safe (ReleaseSafe), the production mode: the guard
/// is an assertion, compiled out where assertions are off. Never installed.
fn addStartupTrip(b: *std.Build, target: std.Build.ResolvedTarget, test_step: *std.Build.Step) void {
    assert(trip.cases.len > 0);
    assert(trip.cases.len <= trip.cases_max);
    const trip_root = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .safe,
    });
    for (trip.cases, 0..) |trip_case, index| {
        const trip_options = b.addOptions();
        trip_options.addOption(u32, "case_index", @intCast(index));
        const module = b.createModule(.{
            .root_source_file = b.path("sim/startup_trip.zig"),
            .target = target,
            .optimize = .safe,
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
