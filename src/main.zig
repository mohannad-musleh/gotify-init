const std = @import("std");
const build_zig_zon = @import("build.zig.zon");
const argsParser = @import("args");

const project_name = @tagName(build_zig_zon.name);
const version = build_zig_zon.version;
const description = build_zig_zon.description;

const ExportFormat = enum { json, keyval };

const Options = struct {
    @"gotify-url": ?[]const u8 = null,
    @"gotify-client-token": ?[]const u8 = null,
    @"gotify-user-username": ?[]const u8 = null,
    @"gotify-user-password": ?[]const u8 = null,
    output: ?[]const u8 = null,
    format: ExportFormat = .json,
    help: bool = false,
    version: bool = false,

    pub const shorthands = .{
        .o = "output",
        .f = "format",
        .t = "gotify-client-token",
        .u = "gotify-user-username",
        .p = "gotify-user-password",
        .h = "help",
        .v = "version",
    };

    pub const meta = .{
        .usage_summary =
        \\[OPTIONS] <applications>
        \\
        \\Authentication:
        \\  The Gotify need a previliged entity to be able to read and/or create applications.
        \\  To authenticate with Gotify, there are two ways:
        \\    - Basic authentication: by providing an explicit username and password of an admin user.
        \\    - Client Token: A special key to identify applications (this CLI for example), such token can be created by visitng Gotify web page. (RECOMMENDED)
        \\
        \\  Basic Auth:
        \\    Pass `--gotify-user-username` and `--gotify-user-password` flags and/or set `GOTIFY_AUTH_USERNAME` and `GOTIFY_AUTH_PASSWORD` environment variables
        \\    NOTES:
        \\      - Flags have higher precedence over environment variables.
        \\      - You can omit the password and you will be promited to enter it later.
        \\
        \\  Client Token:
        \\    Pass `--gotify-client-token` flag or set GOTIFY_CLIENT_TOKEN environment variable.
        \\    NOTES:
        \\      - Flags have higher precedence over environment variables.
        \\      - Client Token has higher precedence over Basic Auth, if both passed, the "Basic Auth" will not be used.
        ,
        .full_text = description,
        .option_docs = .{
            .@"gotify-url" = "The base url for Gotify server (default: GOTIFY_URL environment variable value).",
            .@"gotify-client-token" = "The Gotify's authentication token (Client Token), (default: GOTIFY_CLIENT_TOKEN environment variable value).",
            .@"gotify-user-username" = "The Gotify's username for basic authentication (default: GOTIFY_AUTH_USERNAME environment variable value).",
            .@"gotify-user-password" = "The Gotify's user password for basic authentication (default: GOTIFY_AUTH_PASSWORD environment variable value).",
            .output = "The path to the file to write the output/result into (by default, the result will be printed to stdout)",
            .format = std.fmt.comptimePrint("the output format (default: json). available opetions: {s}", .{comptimeJoin(std.meta.fieldNames(ExportFormat), ", ")}),
            .help = "Print this help and exit.",
            .version = "Display the version of " ++ project_name ++ " and exit.",
        },
    };
};

pub fn main() u8 {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const parsed_args = argsParser.parseForCurrentProcess(Options, arena, .print) catch return 1;
    const options = parsed_args.options;
    const positionals = parsed_args.positionals;
    defer parsed_args.deinit();

    if (options.help) {
        argsParser.printHelp(
            Options,
            parsed_args.executable_name orelse project_name,
            stdout,
        ) catch return 1;
        stdout.flush() catch return 1;
        return 0;
    }

    if (options.version) {
        stdout.print("{s}\n", .{version}) catch return 1;
        stdout.flush() catch return 1;

        return 0;
    }

    if (positionals.len < 1) {
        std.debug.print("Specify at least on application to be created\n", .{});
        return 1;
    }

    const env = std.process.getEnvMap(arena) catch |err| {
        std.debug.print("Failed to get env map: {s}\n", .{@errorName(err)});
        return 1;
    };

    const output = options.output orelse "<stdout>";
    const format = options.format;
    const gotify_uri_str = options.@"gotify-url" orelse env.get("GOTIFY_URL") orelse "";
    if (gotify_uri_str.len < 1) {
        std.debug.print("--gotify_url is required\n", .{});
        return 1;
    }

    const gotify_uri = std.Uri.parse(gotify_uri_str) catch |err| {
        std.debug.print("Failed to parse Gotify URL: {s}\n", .{@errorName(err)});
        return 1;
    };
    const gotify_client_token = options.@"gotify-client-token" orelse env.get("GOTIFY_CLIENT_TOKEN");
    const username = options.@"gotify-user-username" orelse env.get("GOTIFY_AUTH_USERNAME");
    const password = options.@"gotify-user-password" orelse env.get("GOTIFY_AUTH_PASSWORD");

    stdout.print("CLI Input:\n", .{}) catch return 1;
    stdout.print("Gotify URL: {f}\n", .{gotify_uri}) catch return 1;
    stdout.print("Gotify Client Token: {?s}\n", .{gotify_client_token}) catch return 1;
    stdout.print("Gotify User's Username: {?s}\n", .{username}) catch return 1;
    stdout.print("Gotify User's Password: {?s}\n", .{password}) catch return 1;
    stdout.print("Output: {s} (in {s} format)\n", .{ output, @tagName(format) }) catch return 1;
    stdout.print("Application(s) to create: {s}\n", .{std.mem.join(arena, ", ", positionals) catch return 1}) catch return 1;
    stdout.flush() catch return 1;

    return 0;
}

fn comptimeJoin(comptime parts: []const []const u8, comptime sep: []const u8) []const u8 {
    comptime {
        if (parts.len < 1) {
            return "";
        }

        var result_len = 0;
        for (parts) |part| result_len += part.len + sep.len;
        var result: [result_len]u8 = undefined;

        var idx: usize = 0;
        for (parts, 0..) |part, current_idx| {
            // copy part
            for (part) |character| {
                result[idx] = character;
                idx += 1;
            }

            // copy separator except after last
            if (current_idx < parts.len - 1) {
                for (sep) |b| {
                    result[idx] = b;
                    idx += 1;
                }
            }
        }

        return result[0..result_len];
    }
}
