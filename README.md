# gotify-init

A simple CLI tool that calls [Gotify](https://github.com/gotify)'s API(s) to create applications (if missing)
and export applications' tokens.

> [!WARNING]
> This is an alpha software, and not production ready, built specifically for
> my use case and only tested (manually) for that case. Please read the code
> and make sure it works as you expect before using it.

# Install

You can get the binary from the [GitHub releases](/releases).

> [!WARNING]
> For MacOS version, you need to disable the Gatekeeper for the binary after
> installing it.

> [!NOTE]
> You may need to mark the binary as executable (i.e `chmod +x <binary_name>`)

# Build project

Clone repository, make sure you have a compatible Zig version (check
`build.zig.zon` file), and run the build command.

```shell
zig build
```

The output executable will be stored in `./zig-out/bin/gotify_init`.


## run the project
If you want to build and run the project immediately, use `run` build subcommand.

```shell
zig build run
```

