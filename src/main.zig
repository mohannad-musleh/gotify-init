const std = @import("std");
const build_zig_zon = @import("build.zig.zon");
const argsParser = @import("args");
const http = std.http;
const Base64StandardEncoder = std.base64.standard.Encoder;

const ExportFormat = enum { json, keyval };

const Options = struct {
    @"gotify-base-url": ?[]const u8 = null,
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
        .l = "gotify-base-url",
        .t = "gotify-client-token",
        .u = "gotify-user-username",
        .p = "gotify-user-password",
        .h = "help",
        .v = "version",
    };

    pub const meta = .{
        .usage_summary = "[OPTIONS] <applications>",
        .full_text = description ++ "\n\n" ++ (
            \\NOTE: Applications' names are case-sensitive.
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
        ),
        .option_docs = .{
            .@"gotify-base-url" = "The base url for Gotify server (default: GOTIFY_BASE_URL environment variable value).",
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

const project_name = @tagName(build_zig_zon.name);
const version = build_zig_zon.version;
const description = build_zig_zon.description;

const BASIC_AUTH_HEADER_NAME = "Authorization";
const GOTIFY_CLIENT_TOKEN_HEADER_NAME = "X-Gotify-Key";

const GotifyApplication = struct {
    id: usize, // Application unique identifier.
    name: []const u8, // The application name. This is how the application should be displayed to the user. (note: not unique)
    defaultPriority: usize = 0, // The default priority of messages sent by this application. Defaults to 0.
    token: []const u8, // The application token. used for authentication.
    image: []const u8, // The image of the application. example: image/image.jpeg
    description: ?[]const u8,
    internal: bool, // Whether the application is an internal application. Internal applications should not be deleted.
    lastUsed: ?[]const u8, // The last time the application token was used. example: 2019-01-01T00:00:00Z
};

const CreateApplicationPayload = struct {
    name: []const u8, // The application name. This is how the application should be displayed to the user. (note: not unique)
    description: ?[]const u8 = null,
    defaultPriority: ?usize = null, // The default priority of messages sent by this application. Defaults to 0.
};

const Gotify = struct {
    pub fn create_application(
        client: *http.Client,
        gotify_base_uri: *std.Uri,
        auth_header: http.Header,
        application_details: CreateApplicationPayload,
    ) !GotifyApplication {
        const allocator = client.allocator;
        var response_body: std.Io.Writer.Allocating = .init(allocator);
        defer response_body.deinit();

        const payload = try std.json.Stringify.valueAlloc(
            allocator,
            application_details,
            .{ .emit_null_optional_fields = false },
        );
        defer allocator.free(payload);

        gotify_base_uri.path = .{ .raw = "/application" };
        const response = try client.fetch(.{
            .method = .POST,
            .location = .{ .uri = gotify_base_uri.* },
            .payload = payload,
            .response_writer = &response_body.writer,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                auth_header,
            },
        });

        const body_str = try response_body.toOwnedSlice();

        if (response.status != .ok) {
            std.debug.print("Failed to call {f}: status code: {s} ({d}) | body: {s}\n", .{ gotify_base_uri, @tagName(response.status), response.status, body_str });
            return error.InvalidRequest;
        }

        const parsed_body = std.json.parseFromSlice(
            GotifyApplication,
            allocator,
            body_str,
            .{ .ignore_unknown_fields = true, .duplicate_field_behavior = .@"error", .parse_numbers = true },
        ) catch |err| {
            std.debug.print("Failed to parse response body json: {s}\n", .{@errorName(err)});
            return error.InvalidResponseBody;
        };

        return parsed_body.value;
    }

    pub fn get_applications(
        client: *http.Client,
        gotify_base_uri: *std.Uri,
        auth_header: http.Header,
    ) ![]GotifyApplication {
        const allocator = client.allocator;
        var response_body: std.Io.Writer.Allocating = .init(allocator);
        defer response_body.deinit();

        gotify_base_uri.path = .{ .raw = "/application" };
        const response = try client.fetch(.{
            .location = .{ .uri = gotify_base_uri.* },
            .response_writer = &response_body.writer,
            .extra_headers = &.{
                auth_header,
            },
        });

        const body_str = try response_body.toOwnedSlice();

        if (response.status != .ok) {
            std.debug.print("Failed to call {f}: status code: {s} ({d}) | body: {s}\n", .{ gotify_base_uri, @tagName(response.status), response.status, body_str });
            return error.InvalidRequest;
        }

        const parsed_body = std.json.parseFromSlice(
            []GotifyApplication,
            allocator,
            body_str,
            .{ .ignore_unknown_fields = true, .duplicate_field_behavior = .@"error", .parse_numbers = true },
        ) catch |err| {
            std.debug.print("Failed to parse response body json: {s}\n", .{@errorName(err)});
            return error.InvalidResponseBody;
        };

        return parsed_body.value;
    }
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

    const gotify_base_uri_str = options.@"gotify-base-url" orelse env.get("GOTIFY_BASE_URL") orelse "";
    if (gotify_base_uri_str.len < 1) {
        std.debug.print("--gotify_url is required\n", .{});
        return 1;
    }

    var gotify_base_uri = std.Uri.parse(gotify_base_uri_str) catch |err| {
        std.debug.print("Failed to parse Gotify URL: {s}\n", .{@errorName(err)});
        return 1;
    };
    const gotify_client_token = std.mem.trim(u8, options.@"gotify-client-token" orelse env.get("GOTIFY_CLIENT_TOKEN") orelse "", &std.ascii.whitespace);
    const username = std.mem.trim(u8, options.@"gotify-user-username" orelse env.get("GOTIFY_AUTH_USERNAME") orelse "", &std.ascii.whitespace);

    const auth_header: http.Header = if (gotify_client_token.len > 0) blk: {
        break :blk .{
            .name = GOTIFY_CLIENT_TOKEN_HEADER_NAME,
            .value = gotify_client_token,
        };
    } else if (username.len > 0) blk: {
        var basic_auth_arena_allocator = std.heap.ArenaAllocator.init(arena);
        defer basic_auth_arena_allocator.deinit();
        const temp_arena = basic_auth_arena_allocator.allocator();

        const password: []const u8 = pblk: {
            const p = options.@"gotify-user-password" orelse env.get("GOTIFY_AUTH_PASSWORD") orelse "";
            if (p.len > 0) {
                break :pblk p;
            } else {
                break :pblk readPassword(temp_arena, "Enter the gotify user password: ") catch |err| {
                    std.debug.print("Failed to read the password: {s}\n", .{@errorName(err)});
                    return 1;
                };
            }
        };

        var allocating_writer: std.Io.Writer.Allocating = .init(temp_arena);
        allocating_writer.ensureTotalCapacity(Base64StandardEncoder.calcSize(username.len + password.len + 1)) catch return oom();
        const writer = &allocating_writer.writer;

        Base64StandardEncoder.encodeWriter(
            writer,
            std.fmt.allocPrint(temp_arena, "{s}:{s}", .{ username, password }) catch return oom(),
        ) catch |err| {
            std.debug.print("Something went wrong while trying to handle the basic auth header: {s}\n", .{@errorName(err)});
            return 1;
        };

        break :blk .{
            .name = BASIC_AUTH_HEADER_NAME,
            .value = std.fmt.allocPrint(arena, "Basic {s}", .{allocating_writer.written()}) catch return oom(),
        };
    } else {
        std.debug.print("Provide client token or username/password for Gotify authentication\n", .{});
        return 1;
    };

    var client = http.Client{ .allocator = arena };
    defer client.deinit();

    const existing_applications_list = Gotify.get_applications(&client, &gotify_base_uri, auth_header) catch |err| {
        std.debug.print("Failed to retrieve Gotify applications: {s}\n", .{@errorName(err)});
        return 1;
    };
    defer arena.free(existing_applications_list);

    var applications = std.hash_map.StringHashMap(*const GotifyApplication).init(arena);
    defer applications.deinit();

    applications.ensureTotalCapacity(@intCast(existing_applications_list.len + positionals.len)) catch return oom();
    for (existing_applications_list) |*app| {
        std.debug.print("{d}: {s} (token: {s})\n", .{ app.id, app.name, app.token });
        applications.putAssumeCapacity(app.name, app);
    }

    var missing_applications = std.hash_map.StringHashMap(void).init(arena);
    defer missing_applications.deinit();
    missing_applications.ensureTotalCapacity(@intCast(positionals.len)) catch return oom();

    for (positionals) |app_name| {
        if (applications.contains(app_name)) continue;
        missing_applications.putAssumeCapacity(app_name, {});
    }

    var iter = missing_applications.keyIterator();
    while (iter.next()) |app_name| {
        const payload: CreateApplicationPayload = .{
            .name = app_name.*,
        };
        const new_app = Gotify.create_application(&client, &gotify_base_uri, auth_header, payload) catch |err| {
            std.debug.print("Failed to create \"{s}\" applcation: {s}\n", .{ app_name.*, @errorName(err) });
            return 1;
        };

        applications.put(new_app.name, &new_app) catch return oom();
    }

    std.debug.print("----------------------[AFTER]-----------------\n", .{});
    var apps_iter = applications.iterator();
    while (apps_iter.next()) |entry| {
        const app = entry.value_ptr.*.*;
        std.debug.print("{d}: {s} (token: {s})\n", .{ app.id, app.name, app.token });
    }

    // TODO:
    // - find a way to sort applications by id (for consistent output)
    // - print the output in the target format

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

inline fn clear(stdout: *std.Io.Writer) void {
    stdout.writeAll("\x1B[2J\x1B[H") catch return; // clear screen
    stdout.flush() catch return;
}

inline fn oom() u8 {
    std.debug.print("OUT OF MEMORY!\n", .{});
    return 1;
}

fn readPassword(allocator: std.mem.Allocator, comptime msg: []const u8) ![]const u8 {
    std.debug.print(msg, .{});
    const stdin = std.fs.File.stdin();
    var stdin_buffer: [1024]u8 = undefined;
    // See: https://github.com/eltNEG/passprompt/blob/1ef9720c9fb559a0364c2ec47fd7d4cdba6f2301/src/root.zig#L7
    var term = try std.posix.tcgetattr(stdin.handle);
    defer {
        // Defer used to garanty the ECHO mode is (re)enabled even if the logic fails.
        term.lflag.ECHO = true;
        std.posix.tcsetattr(stdin.handle, .NOW, term) catch {};
    }

    term.lflag.ECHO = false;
    try std.posix.tcsetattr(stdin.handle, .NOW, term);

    var bytes_read: usize = 0;
    while (bytes_read < 1) bytes_read = (try stdin.read(&stdin_buffer)) - 1;

    return allocator.dupe(u8, stdin_buffer[0..bytes_read]);
}
