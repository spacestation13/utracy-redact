use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

// .utracy file constants
const HEADER_SIZE: usize = 1200;
const FILE_SIGNATURE: u64 = 0x6D64796361727475;
const FILE_VERSION: u32 = 2;
const SIG_OFFSET: usize = 0;
const VER_OFFSET: usize = 8;

const BUF_SIZE: usize = 8 * 1024 * 1024; // 8 MiB

const REDACTED: &str = "<redacted>";

/// Rewrite the srcloc table of a .utracy file, replacing name/function/file
/// fields with <redacted> for any srcloc whose source file path contains
/// "+secret".
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the input .utracy file
    input: PathBuf,

    /// Output path (default: <stem>.redacted.utracy in the same dir)
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Overwrite the input file in-place (mutually exclusive with --output)
    #[arg(long, conflicts_with = "output")]
    in_place: bool,

    /// Print what would be redacted without writing any output
    #[arg(long)]
    dry_run: bool,

    /// Substrings matched against the srcloc file path (case-insensitive, repeatable)
    #[arg(long = "file-marker", value_name = "SUBSTR", default_values = ["code_secret"])]
    file_markers: Vec<String>,

    /// Substrings matched against the srcloc function name (case-insensitive, repeatable)
    #[arg(long = "fn-marker", value_name = "SUBSTR", default_values = ["secret"])]
    fn_markers: Vec<String>,
}

// ---------------------------------------------------------------------------
// Length-prefixed string helpers (u32 LE length + raw UTF-8 bytes)
// ---------------------------------------------------------------------------

fn read_lenpfx_string<R: Read>(r: &mut R) -> Result<String> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).context("reading string length")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes).context("reading string bytes")?;
    String::from_utf8(bytes).context("string is not valid UTF-8")
}

fn write_lenpfx_string<W: Write>(w: &mut W, s: &str) -> Result<()> {
    w.write_all(&(s.len() as u32).to_le_bytes()).context("writing string length")?;
    w.write_all(s.as_bytes()).context("writing string bytes")
}

// ---------------------------------------------------------------------------
// Output path resolution
// ---------------------------------------------------------------------------

fn resolve_output(cli: &Cli) -> Result<Option<PathBuf>> {
    if cli.dry_run {
        return Ok(None);
    }

    if cli.in_place {
        return Ok(None); // we'll use a temp file; handled separately
    }

    let canonical_in = fs::canonicalize(&cli.input)
        .unwrap_or_else(|_| cli.input.clone());

    if let Some(p) = &cli.output {
        let canonical_out = fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        if canonical_in == canonical_out {
            bail!("--output path is the same as the input file; use --in-place to overwrite");
        }
        return Ok(Some(p.clone()));
    }

    let dir = canonical_in.parent().unwrap_or_else(|| Path::new("."));
    let stem = canonical_in
        .file_stem()
        .context("input has no file stem")?
        .to_string_lossy();
    let derived = dir.join(format!("{stem}.redacted.utracy"));

    if canonical_in == fs::canonicalize(&derived).unwrap_or_else(|_| derived.clone()) {
        bail!(
            "derived output path ({}) equals the input path; \
             use -o to specify a different path or --in-place to overwrite",
            derived.display()
        );
    }

    Ok(Some(derived))
}

// ---------------------------------------------------------------------------
// Core redaction logic
// ---------------------------------------------------------------------------

fn process<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    dry_run: bool,
    file_markers: &[String],
    fn_markers: &[String],
) -> Result<Vec<String>> {
    // -- Header (1200 bytes - calculated) -----------------------------------
    let mut header = [0u8; HEADER_SIZE];
    reader
        .read_exact(&mut header)
        .context("reading file header (expected 1200 bytes)")?;

    // Validate signature (u64 LE at offset 0)
    let sig = u64::from_le_bytes(header[SIG_OFFSET..SIG_OFFSET + 8].try_into().unwrap());
    if sig != FILE_SIGNATURE {
        bail!(
            "invalid .utracy signature: got 0x{sig:016X}, expected 0x{FILE_SIGNATURE:016X}"
        );
    }

    // Validate version (u32 LE at offset 8)
    let ver = u32::from_le_bytes(header[VER_OFFSET..VER_OFFSET + 4].try_into().unwrap());
    if ver != FILE_VERSION {
        bail!("unsupported .utracy version: got {ver}, expected {FILE_VERSION}");
    }

    if !dry_run {
        writer.write_all(&header).context("writing header")?;
    }

    // -- srcloc_count (u32 LE) -----------------------------------------------
    let mut count_buf = [0u8; 4];
    reader
        .read_exact(&mut count_buf)
        .context("reading srcloc_count")?;
    let srcloc_count = u32::from_le_bytes(count_buf);

    if !dry_run {
        writer
            .write_all(&count_buf)
            .context("writing srcloc_count")?;
    }

    // -- Srcloc table --------------------------------------------------------
    let file_markers_lower: Vec<String> = file_markers.iter().map(|m| m.to_ascii_lowercase()).collect();
    let fn_markers_lower: Vec<String> = fn_markers.iter().map(|m| m.to_ascii_lowercase()).collect();
    let mut redacted_fns = Vec::new();

    for _ in 0..srcloc_count {
        let name = read_lenpfx_string(reader).context("reading srcloc.name")?;
        let function = read_lenpfx_string(reader).context("reading srcloc.function")?;
        let file = read_lenpfx_string(reader).context("reading srcloc.file")?;

        let mut line_buf = [0u8; 4];
        reader
            .read_exact(&mut line_buf)
            .context("reading srcloc.line")?;
        let mut color_buf = [0u8; 4];
        reader
            .read_exact(&mut color_buf)
            .context("reading srcloc.color")?;

        let file_lower = file.to_ascii_lowercase();
        let fn_lower = function.to_ascii_lowercase();
        let secret = file_markers_lower.iter().any(|m| file_lower.contains(m.as_str()))
            || fn_markers_lower.iter().any(|m| fn_lower.contains(m.as_str()));

        if secret {
            redacted_fns.push(function.clone());
        }

        if !dry_run {
            let (out_name, out_fn, out_file): (&str, &str, &str) = if secret {
                (REDACTED, REDACTED, REDACTED)
            } else {
                (&name, &function, &file)
            };
            write_lenpfx_string(writer, out_name).context("writing srcloc.name")?;
            write_lenpfx_string(writer, out_fn).context("writing srcloc.function")?;
            write_lenpfx_string(writer, out_file).context("writing srcloc.file")?;
            writer.write_all(&line_buf).context("writing srcloc.line")?;
            writer.write_all(&color_buf).context("writing srcloc.color")?;
        }
    }

    // -- Event stream ----------- -------------------------------------------
    if !dry_run {
        std::io::copy(reader, writer).context("copying event stream")?;
    }

    Ok(redacted_fns)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Validate input exists
    if !cli.input.exists() {
        bail!("input file not found: {}", cli.input.display());
    }

    let output_path = resolve_output(&cli)?;

    // Determine actual output: temp file for --in-place, path for normal
    let temp_path = if cli.in_place && !cli.dry_run {
        let dir = cli
            .input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let stem = cli
            .input
            .file_stem()
            .context("input has no file stem")?
            .to_string_lossy();
        Some(dir.join(format!("{stem}.redact_tmp_{}.utracy", std::process::id())))
    } else {
        None
    };

    // Open input
    let input_file = File::open(&cli.input)
        .with_context(|| format!("opening input: {}", cli.input.display()))?;
    let mut reader = BufReader::with_capacity(BUF_SIZE, input_file);

    // Open output / temp
    let effective_out = temp_path.as_ref().or(output_path.as_ref());

    let redacted: Vec<String>;

    if let Some(out) = effective_out {
        let out_file = File::create(out)
            .with_context(|| format!("creating output: {}", out.display()))?;
        let mut writer = BufWriter::with_capacity(BUF_SIZE, out_file);

        redacted = process(&mut reader, &mut writer, false, &cli.file_markers, &cli.fn_markers)?;

        writer.flush().context("flushing output")?;
    } else {
        // dry_run
        redacted = process(
            &mut reader,
            &mut std::io::sink(),
            cli.dry_run,
            &cli.file_markers,
            &cli.fn_markers,
        )?;
    }

    // rename for --in-place
    if let Some(tmp) = &temp_path {
        fs::rename(tmp, &cli.input).with_context(|| {
            format!(
                "renaming temp file {} over {}",
                tmp.display(),
                cli.input.display()
            )
        })?;
    }

    let count = redacted.len();
    if cli.dry_run {
        if count == 0 {
            println!("Dry run: no source locations would be redacted.");
        } else {
            println!("Dry run: would redact {count} source locations:");
            for f in &redacted {
                println!("  {f}");
            }
        }
    } else {
        if count == 0 {
            println!("No source locations were redacted.");
        } else {
            println!("Redacted {count} source locations.");
        }

        let final_out = if cli.in_place {
            cli.input.display().to_string()
        } else {
            output_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        };
        println!("Output: {final_out}");
    }

    Ok(())
}
