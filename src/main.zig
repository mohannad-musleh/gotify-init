const std = @import("std");
const build_zig_zon = @import("build.zig.zon");
const argsParser = @import("args");
const http = std.http;
const Base64StandardEncoder = std.base64.standard.Encoder;

const project_name = @tagName(build_zig_zon.name);
const version = build_zig_zon.version;
const description = build_zig_zon.description;

const BASIC_AUTH_HEADER_NAME = "Authorization";
const GOTIFY_CLIENT_TOKEN_HEADER_NAME = "X-Gotify-Key";

const ExportFormat = enum { json, dotenv };

const ApplicationArrayList = std.ArrayList(GotifyApplication);

const Options = struct {
    @"gotify-base-url": ?[]const u8 = null,
    @"gotify-client-token": ?[]const u8 = null,
    @"gotify-user-username": ?[]const u8 = null,
    @"gotify-user-password": ?[]const u8 = null,
    output: ?[]const u8 = null,
    format: ExportFormat = .json,
    @"json-output-map": ?[]const u8 = null,
    @"json-format-keys": bool = false,
    @"json-exclude-not-mapped-applications": bool = false,
    help: bool = false,
    version: bool = false,

    pub const wrap_len = 100;

    pub const shorthands = .{
        .o = "output",
        .f = "format",
        .l = "gotify-base-url",
        .t = "gotify-client-token",
        .u = "gotify-user-username",
        .p = "gotify-user-password",
        .k = "json-format-keys",
        .e = "json-exclude-not-mapped-applications",
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
            \\
            \\Output format:
            \\  - json: a json string will be printed with a root object contains all apps names as attribute/key and the for each one is the application token.
            \\    - You can specify --json-output-map to customize the output
            \\      E.g --json-output-map '{"gotify_app1": "gotify_app_1_token", "gotify_app2": "a.deep.attribute.GOTIFY_TOKEN"}'
            \\      The output will be:
            \\      {
            \\          "gotify_app_1_token": "{token of 'gotify_app1' app}",
            \\          "a": {
            \\              "deep": {
            \\                  "attribute": {
            \\                      "GOTIFY_TOKEN": "{token of 'gotify_app2' app}"
            \\                  }
            \\              }
            \\          }
            \\      }
            \\
            \\  - dotenv: a key-value format that can be used with dotenv (.env) format. the key is the application name and the value is the application token.
            \\    - NOTE: the application name/key will be modified, all spaces will be replaced with `_` (underscore) and all letters will be capitalized.
        ),
        .option_docs = .{
            .@"gotify-base-url" = "The base url for Gotify server (default: GOTIFY_BASE_URL environment variable value).",
            .@"gotify-client-token" = "The Gotify's authentication token (Client Token), (default: GOTIFY_CLIENT_TOKEN environment variable value).",
            .@"gotify-user-username" = "The Gotify's username for basic authentication (default: GOTIFY_AUTH_USERNAME environment variable value).",
            .@"gotify-user-password" = "The Gotify's user password for basic authentication (default: GOTIFY_AUTH_PASSWORD environment variable value).",
            .output = "The path to the file to write the output/result into (by default, the result will be printed to stdout)",
            .format = std.fmt.comptimePrint("the output format (default: json). available opetions: {s}", .{comptimeJoin(std.meta.fieldNames(ExportFormat), ", ")}),
            .@"json-output-map" = "For \"json\" output format, you can specify a json string " ++
                "to map where the token of each application token will be stored " ++
                "in the output. Any left out app names, they will be stored in " ++
                "the default plcace (root level).",
            .@"json-exclude-not-mapped-applications" = "When the output format " ++
                "is json, and the --json-output-map is specifed, passing " ++
                "this flag will exclude the Gotify applications that not " ++
                "included in the map.",
            .@"json-format-keys" = "for json output format, passing this flag " ++
                "to make sure all attribute names are usable as environment " ++
                "variable name (by replacing the spaces with \"_\" and " ++
                "capitalize all letters).",
            .help = "Print this help and exit.",
            .version = "Display the version of " ++ project_name ++ " and exit.",
        },
    };
};

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
    var stdout = &stdout_writer.interface;

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

    const json_output_map_str = options.@"json-output-map";
    var parsed_json_output_map: ?std.json.Parsed(std.json.Value) = null;
    var json_output_map: ?std.json.Value = null;

    if (options.format == .json) {
        if (json_output_map_str) |m| {
            parsed_json_output_map = std.json.parseFromSlice(std.json.Value, arena, m, .{ .parse_numbers = false }) catch {
                std.debug.print("Invalid json value for --json-output-map flag", .{});
                return 1;
            };

            if (parsed_json_output_map.?.value == .object) {
                json_output_map = parsed_json_output_map.?.value;
            } else {
                std.debug.print("The json output map must be a single root object and all keys and values must be strings\n", .{});
                return 1;
            }
        }
    }

    const env = std.process.getEnvMap(arena) catch |err| {
        std.debug.print("Failed to get env map: {s}\n", .{@errorName(err)});
        return 1;
    };

    const gotify_base_uri_str = options.@"gotify-base-url" orelse env.get("GOTIFY_BASE_URL") orelse "";
    if (gotify_base_uri_str.len < 1) {
        std.debug.print("gotify base url is required\n", .{});
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

    const max_applications_count = existing_applications_list.len + positionals.len;

    var applications = ApplicationArrayList.initCapacity(arena, max_applications_count) catch return oom();
    defer applications.deinit(arena);

    var applications_names_set = std.hash_map.StringHashMap(void).init(arena);
    defer applications_names_set.deinit();
    applications_names_set.ensureTotalCapacity(@truncate(max_applications_count)) catch return oom();

    for (existing_applications_list) |app| {
        applications_names_set.putAssumeCapacity(app.name, {});
        applications.appendAssumeCapacity(app);
    }

    var missing_applications_names = std.hash_map.StringHashMap(void).init(arena);
    defer missing_applications_names.deinit();
    missing_applications_names.ensureTotalCapacity(@intCast(positionals.len)) catch return oom();

    for (positionals) |p| {
        const app_name = std.mem.trim(u8, p, &std.ascii.whitespace);
        if (app_name.len < 1 or applications_names_set.contains(app_name)) continue;
        missing_applications_names.putAssumeCapacity(app_name, {});
        applications_names_set.putAssumeCapacity(app_name, {}); // added here to prevent duplicate applications' names.
    }

    {
        var iter = missing_applications_names.keyIterator();
        while (iter.next()) |app_name_ptr| {
            const app_name = app_name_ptr.*;
            const new_app = Gotify.create_application(&client, &gotify_base_uri, auth_header, .{ .name = app_name }) catch |err| {
                std.debug.print("Failed to create \"{s}\" applcation: {s}\n", .{ app_name, @errorName(err) });
                return 1;
            };

            applications.appendAssumeCapacity(new_app);
        }
    }

    var output_arena_allocator = std.heap.ArenaAllocator.init(arena);
    defer output_arena_allocator.deinit();
    const output_allocator = output_arena_allocator.allocator();

    switch (options.format) {
        .json => {
            const e = struct {
                fn e(err: anyerror) u8 {
                    std.debug.print("Something went wrong while writing the json: {s}\n", .{@errorName(err)});
                    return 1;
                }
            }.e;

            var s: std.json.Stringify = .{ .writer = stdout, .options = .{ .whitespace = .minified } };
            if (json_output_map) |f| {
                var applications_map: std.StringHashMap(GotifyApplication) = .init(output_allocator);
                applications_map.ensureUnusedCapacity(@intCast(applications.items.len)) catch return oom();
                for (applications.items) |app| applications_map.putAssumeCapacity(app.name, app);

                var output_object: std.json.Value = .{ .object = .init(output_allocator) };

                for (f.object.keys()) |gotify_app_key| {
                    const gotify_app_token_attribute_path = kblk: {
                        if (f.object.get(gotify_app_key)) |kv| if (kv == .string) break :kblk kv.string;

                        std.debug.print("The json output map keys and values must be strings\n", .{});
                        return 1;
                    };

                    var rev_iter = std.mem.splitBackwardsScalar(u8, gotify_app_token_attribute_path, '.');

                    var child_key: ?[]const u8 = null;
                    var child_value: ?std.json.Value = null;
                    while (rev_iter.next()) |part| {
                        const app = applications_map.get(gotify_app_key) orelse {
                            std.debug.print("Gotify application \"{s}\" not found\n.", .{gotify_app_key});
                            return 1;
                        };

                        if (child_value == null) {
                            child_key = part;
                            child_value = .{ .string = app.token };
                        } else {
                            var o: std.json.Value = .{ .object = .init(output_allocator) };
                            o.object.put(child_key.?, child_value.?) catch return oom();
                            child_key = part;
                            child_value = o;
                            if (rev_iter.index == null) output_object.object.put(child_key.?, child_value.?) catch return oom();
                        }
                    }
                }

                if (!options.@"json-exclude-not-mapped-applications") {
                    for (toOwnedOrderdSlice(output_allocator, &applications) catch return oom()) |app| {
                        const app_name = if (options.@"json-format-keys") fblk: {
                            const app_name = std.ascii.allocUpperString(output_allocator, app.name) catch return oom();
                            _ = std.mem.replace(u8, app_name, " ", "_", app_name);
                            break :fblk app_name;
                        } else app.name;
                        if (!f.object.contains(app.name)) {
                            _ = output_object.object.getOrPutValue(app_name, .{ .string = app.token }) catch return oom();
                        }
                    }
                }
                var w: std.Io.Writer.Allocating = .init(output_allocator);
                defer w.deinit();
                std.json.fmt(output_object, .{}).format(stdout) catch |err| std.debug.print("Failed to stringify the json: {s}\n", .{@errorName(err)});

                stdout.flush() catch return 1;
            } else {
                s.beginObject() catch |err| return e(err);
                for (toOwnedOrderdSlice(output_allocator, &applications) catch return oom()) |app| {
                    const app_name = if (options.@"json-format-keys") fblk: {
                        const app_name = std.ascii.allocUpperString(output_allocator, app.name) catch return oom();
                        _ = std.mem.replace(u8, app_name, " ", "_", app_name);
                        break :fblk app_name;
                    } else app.name;
                    s.objectField(app_name) catch |err| return e(err);
                    s.write(app.token) catch |err| return e(err);
                }
                s.endObject() catch |err| return e(err);
                stdout.print("\n", .{}) catch return 1;
                stdout.flush() catch return 1;
            }
        },
        .dotenv => {
            for (toOwnedOrderdSlice(output_allocator, &applications) catch return oom()) |app| {
                const app_name = std.ascii.allocUpperString(output_allocator, app.name) catch return oom();
                _ = std.mem.replace(u8, app_name, " ", "_", app_name);
                stdout.print("{s}={s}\n", .{ app_name, app.token }) catch return 1;
            }
            stdout.flush() catch return 1;
        },
    }

    return 0;
}

inline fn comptimeJoin(comptime parts: []const []const u8, comptime sep: []const u8) []const u8 {
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
        // Defer used to guaranty the ECHO mode is (re)enabled even if the logic fails.
        term.lflag.ECHO = true;
        std.posix.tcsetattr(stdin.handle, .NOW, term) catch {};
    }

    term.lflag.ECHO = false;
    try std.posix.tcsetattr(stdin.handle, .NOW, term);

    var bytes_read: usize = 0;
    while (bytes_read < 1) bytes_read = (try stdin.read(&stdin_buffer)) - 1;

    return allocator.dupe(u8, stdin_buffer[0..bytes_read]);
}

fn toOwnedOrderdSlice(allocator: std.mem.Allocator, apps: *ApplicationArrayList) !ApplicationArrayList.Slice {
    const applications_list = apps.toOwnedSlice(allocator) catch |err| return err;
    std.sort.block(
        GotifyApplication,
        applications_list,
        @as(void, {}),
        struct {
            fn lessThan(_: void, app1: GotifyApplication, app2: GotifyApplication) bool {
                return app1.id < app2.id;
            }
        }.lessThan,
    );
    return applications_list;
}
