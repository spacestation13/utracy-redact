# utracy-redact

Redact secret source locations from `.utracy` profiler files.

Defaults are for the [Goonstation](https://github.com/goonstation/goonstation) codebase.

See: 

https://github.com/Dimach/rtracy

https://github.com/ParadiseSS13/byond-tracy

## Usage

Drag and drop your .utracy file on the .exe, or

```
utracy-redact.exe <INPUT> [OPTIONS]
```

### Options

- `-o, --output <PATH>` - write to a specific path (default: `<stem>.redacted.utracy` next to input)
- `--in-place` - overwrite the input file atomically via temp file
- `--dry-run` - show what would be redacted without writing
- `--file-marker <SUBSTR>` - match srclocs whose **file path** contains this substring (case-insensitive, repeatable, default: `code_secret`)
- `--fn-marker <SUBSTR>` - match srclocs whose **function name** contains this substring (case-insensitive, repeatable, default: `secret`)

### Example

```bash
# Redact and generate myfile.redacted.utracy
utracy-redact.exe myfile.utracy

# Dry-run to see what gets redacted
utracy-redact.exe myfile.utracy --dry-run

# Overwrite input in-place
utracy-redact.exe myfile.utracy --in-place

# Custom markers
utracy-redact.exe myfile.utracy --file-marker secret_code --fn-marker internal
```

## How it works

Scans the `.utracy` file's source location table. Replaces `name`, `function`, and `file` fields with `<redacted>` for any srcloc where:

- **file path** contains any `--file-marker` value (case-sensitive), OR
- **function name** contains any `--fn-marker` value (case-insensitive)

The raw event stream is bulk-copied verbatim to preserve binary fidelity.
