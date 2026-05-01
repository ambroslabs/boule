//! `lines` — count Rust source lines, tokei-style, with an impl-vs-test split.
//!
//! Usage: `cargo run --bin lines -- [--per-file|-f|--ls|-l] [PATH]`
//!         (PATH defaults to `src`)
//!
//! Aggregation modes:
//!   * default (`--by-subdir` implicit) — one row per top-level subdirectory
//!     under PATH; files directly in PATH are aggregated into a `.` row.
//!   * `--ls` / `-l` — list each entry directly under PATH: top-level files
//!     get their own row, subdirectories aggregate everything beneath them
//!     into a single row.
//!   * `--per-file` / `-f` — one row per `.rs` file, fully recursive.
//!
//! Each `.rs` file under PATH is classified line-by-line as:
//!   * blank   — only whitespace
//!   * comment — only `//` or `/* */` comments + whitespace
//!   * code    — anything else
//!
//! and *code* lines are further split into impl vs test:
//!   * test = code inside `#[cfg(test)]` item bodies, plus all code in files
//!     declared from a parent module as `#[cfg(test)] mod NAME;`
//!   * impl = the rest
//!
//! Strings, char literals, and comments are tracked while scanning so
//! delimiters inside them don't perturb the classifier.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Default, Clone, Copy)]
struct Counts {
    files: usize,
    lines: usize,
    code_impl: usize,
    code_test: usize,
    comments: usize,
    blanks: usize,
}

impl Counts {
    fn add(&mut self, o: Counts) {
        self.files += o.files;
        self.lines += o.lines;
        self.code_impl += o.code_impl;
        self.code_test += o.code_test;
        self.comments += o.comments;
        self.blanks += o.blanks;
    }
    fn code(&self) -> usize {
        self.code_impl + self.code_test
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    BySubdir,
    PerFile,
    Ls,
}

fn main() -> ExitCode {
    let mut mode = Mode::BySubdir;
    let mut path: Option<PathBuf> = None;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--per-file" | "-f" => mode = Mode::PerFile,
            "--ls" | "-l" => mode = Mode::Ls,
            "--help" | "-h" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            s if s.starts_with('-') => {
                eprintln!("error: unknown flag: {s}");
                eprintln!(
                    "usage: lines [--per-file|-f|--ls|-l] [PATH]   (PATH defaults to `src`)"
                );
                return ExitCode::from(2);
            }
            _ => {
                if path.is_some() {
                    eprintln!("error: multiple paths given");
                    return ExitCode::from(2);
                }
                path = Some(PathBuf::from(&arg));
            }
        }
    }
    let root = path.unwrap_or_else(|| PathBuf::from("src"));

    if !root.exists() {
        eprintln!("error: path not found: {}", root.display());
        return ExitCode::from(1);
    }

    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    files.sort();

    // Pass 1: resolve `#[cfg(test)] mod NAME;` declarations from any file
    // under the root to the actual child source file so it's tagged
    // entirely as test code.
    let mut test_only: BTreeSet<PathBuf> = BTreeSet::new();
    for f in &files {
        let Ok(src) = fs::read_to_string(f) else {
            continue;
        };
        for name in find_test_only_mod_decls(&src) {
            for candidate in resolve_mod_paths(f, &name) {
                if let Ok(c) = candidate.canonicalize() {
                    test_only.insert(c);
                }
            }
        }
    }

    let mut by_dir: BTreeMap<PathBuf, Counts> = BTreeMap::new();
    let mut per_file_rows: Vec<(PathBuf, Counts)> = Vec::with_capacity(files.len());
    let mut total = Counts::default();

    for f in &files {
        let Ok(src) = fs::read_to_string(f) else {
            continue;
        };
        let canon = f.canonicalize().unwrap_or_else(|_| f.clone());
        let is_test = test_only.contains(&canon) || in_cargo_tests_dir(f);
        let counts = classify_file(&src, is_test);
        total.add(counts);
        by_dir.entry(bucket_for(f, &root)).or_default().add(counts);
        per_file_rows.push((f.clone(), counts));
    }

    match mode {
        Mode::BySubdir => print_table(&root, &by_dir, total),
        Mode::PerFile => print_per_file(&root, &per_file_rows, total),
        Mode::Ls => print_ls(&root, &per_file_rows, total),
    }
    ExitCode::SUCCESS
}

// ----- file walk + bucketing ------------------------------------------------

fn collect_rs_files(p: &Path, out: &mut Vec<PathBuf>) {
    let Ok(md) = fs::symlink_metadata(p) else {
        return;
    };
    if md.is_dir() {
        let Ok(rd) = fs::read_dir(p) else {
            return;
        };
        for ent in rd.flatten() {
            let child = ent.path();
            if child.is_dir()
                && let Some(name) = child.file_name().and_then(|n| n.to_str())
                && should_skip_dir(name)
            {
                continue;
            }
            collect_rs_files(&child, out);
        }
    } else if md.is_file() && p.extension().and_then(|e| e.to_str()) == Some("rs") {
        out.push(p.to_path_buf());
    }
}

fn should_skip_dir(name: &str) -> bool {
    // Skip build artifacts and dotdirs encountered during recursion. The
    // user's root path itself is never filtered, so explicit `lines target/`
    // would still scan, but `lines .` won't dive into `./target` or `./.git`.
    name == "target" || name.starts_with('.')
}

fn in_cargo_tests_dir(file: &Path) -> bool {
    // Cargo treats every `.rs` under a crate's `tests/` or `benches/` sibling
    // as integration test / bench code — those files have no `#[cfg(test)]`
    // because the *whole crate* is the test crate. Detect by walking up: a
    // `tests`/`benches` directory whose parent contains a `Cargo.toml`.
    let mut cur = file.parent();
    while let Some(dir) = cur {
        if let Some(name) = dir.file_name().and_then(|n| n.to_str())
            && (name == "tests" || name == "benches")
            && let Some(parent) = dir.parent()
            && parent.join("Cargo.toml").is_file()
        {
            return true;
        }
        cur = dir.parent();
    }
    false
}

fn bucket_for(file: &Path, root: &Path) -> PathBuf {
    let rel = file.strip_prefix(root).unwrap_or(file);
    let mut comps = rel.components();
    let Some(first) = comps.next() else {
        return root.to_path_buf();
    };
    if comps.next().is_some() {
        root.join(first.as_os_str())
    } else {
        root.to_path_buf()
    }
}

// ----- per-line classification ---------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LineKind {
    Blank,
    Comment,
    Code,
}

fn classify_file(src: &str, whole_file_is_test: bool) -> Counts {
    let kinds = classify_lines(src);
    let n = kinds.len();
    let mut is_test = vec![false; n];
    if whole_file_is_test {
        for slot in is_test.iter_mut() {
            *slot = true;
        }
    } else {
        for (s, e) in find_cfg_test_line_ranges(src) {
            let end = e.min(n.saturating_sub(1));
            for slot in &mut is_test[s.min(n)..=end.min(n.saturating_sub(1))] {
                *slot = true;
            }
        }
    }

    let mut c = Counts {
        files: 1,
        lines: n,
        ..Default::default()
    };
    for (i, k) in kinds.iter().enumerate() {
        match k {
            LineKind::Blank => c.blanks += 1,
            LineKind::Comment => c.comments += 1,
            LineKind::Code => {
                if is_test[i] {
                    c.code_test += 1;
                } else {
                    c.code_impl += 1;
                }
            }
        }
    }
    c
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scan {
    Code,
    LineComment,
    BlockComment,
    StringLit,
    RawString(usize), // number of `#` in the opening `r#..."`
}

fn classify_lines(src: &str) -> Vec<LineKind> {
    let bytes = src.as_bytes();
    let mut out: Vec<LineKind> = Vec::new();
    let mut state = Scan::Code;
    let mut block_depth: u32 = 0;
    let mut has_code = false;
    let mut has_comment = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            out.push(line_kind(has_code, has_comment));
            has_code = false;
            has_comment = false;
            if matches!(state, Scan::LineComment) {
                state = Scan::Code;
            }
            i += 1;
            continue;
        }
        match state {
            Scan::Code => {
                if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
                    state = Scan::LineComment;
                    has_comment = true;
                    i += 2;
                    continue;
                }
                if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    state = Scan::BlockComment;
                    block_depth = 1;
                    has_comment = true;
                    i += 2;
                    continue;
                }
                if b == b'r' {
                    // Possible raw string `r"..."` or `r#"..."#` (any number of `#`).
                    let mut hashes = 0usize;
                    let mut j = i + 1;
                    while bytes.get(j) == Some(&b'#') {
                        hashes += 1;
                        j += 1;
                    }
                    if bytes.get(j) == Some(&b'"') {
                        state = Scan::RawString(hashes);
                        has_code = true;
                        i = j + 1;
                        continue;
                    }
                }
                if b == b'b' {
                    // `b"..."` byte string — same close rules as a normal string.
                    if bytes.get(i + 1) == Some(&b'"') {
                        state = Scan::StringLit;
                        has_code = true;
                        i += 2;
                        continue;
                    }
                    // `br"..."` / `br#"..."#` raw byte string.
                    if bytes.get(i + 1) == Some(&b'r') {
                        let mut hashes = 0usize;
                        let mut j = i + 2;
                        while bytes.get(j) == Some(&b'#') {
                            hashes += 1;
                            j += 1;
                        }
                        if bytes.get(j) == Some(&b'"') {
                            state = Scan::RawString(hashes);
                            has_code = true;
                            i = j + 1;
                            continue;
                        }
                    }
                }
                if b == b'"' {
                    state = Scan::StringLit;
                    has_code = true;
                    i += 1;
                    continue;
                }
                if b == b'\'' {
                    has_code = true;
                    if let Some(end) = char_lit_close(bytes, i) {
                        i = end + 1;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if !b.is_ascii_whitespace() {
                    has_code = true;
                }
                i += 1;
            }
            Scan::LineComment => {
                has_comment = true;
                i += 1;
            }
            Scan::BlockComment => {
                has_comment = true;
                if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    block_depth += 1;
                    i += 2;
                    continue;
                }
                if b == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    block_depth -= 1;
                    i += 2;
                    if block_depth == 0 {
                        state = Scan::Code;
                    }
                    continue;
                }
                i += 1;
            }
            Scan::StringLit => {
                has_code = true;
                if b == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if b == b'"' {
                    state = Scan::Code;
                }
                i += 1;
            }
            Scan::RawString(hashes) => {
                has_code = true;
                if b == b'"' {
                    let mut k = 0;
                    while k < hashes && bytes.get(i + 1 + k) == Some(&b'#') {
                        k += 1;
                    }
                    if k == hashes {
                        state = Scan::Code;
                        i += 1 + hashes;
                        continue;
                    }
                }
                i += 1;
            }
        }
    }
    if !src.is_empty() && !src.ends_with('\n') {
        out.push(line_kind(has_code, has_comment));
    }
    out
}

fn line_kind(has_code: bool, has_comment: bool) -> LineKind {
    if has_code {
        LineKind::Code
    } else if has_comment {
        LineKind::Comment
    } else {
        LineKind::Blank
    }
}

fn char_lit_close(bytes: &[u8], start: usize) -> Option<usize> {
    // Char literals close within a small bounded window; lifetimes never have a
    // closing `'`, so a bounded forward scan distinguishes the two reliably.
    let limit = (start + 12).min(bytes.len());
    let mut j = start + 1;
    while j < limit {
        match bytes[j] {
            b'\n' => return None,
            b'\\' if j + 1 < bytes.len() => {
                j += 2;
                continue;
            }
            b'\'' => return Some(j),
            _ => j += 1,
        }
    }
    None
}

// ----- #[cfg(test)] discovery ----------------------------------------------

fn find_test_only_mod_decls(src: &str) -> Vec<String> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = find_subseq(&bytes[i..], b"#[cfg(test)]") {
        let attr_start = i + rel;
        let attr_end = attr_start + b"#[cfg(test)]".len();
        let (term, kind) = scan_item_head(src, attr_end);
        if matches!(kind, ItemKind::ModFile) {
            if let Some(name) = parse_mod_name(&src[attr_end..term]) {
                out.push(name);
            }
        }
        i = attr_end;
    }
    out
}

fn find_cfg_test_line_ranges(src: &str) -> Vec<(usize, usize)> {
    let bytes = src.as_bytes();
    let starts = line_starts(src);
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while let Some(rel) = find_subseq(&bytes[i..], b"#[cfg(test)]") {
        let attr_start = i + rel;
        let attr_end = attr_start + b"#[cfg(test)]".len();
        let (term, kind) = scan_item_head(src, attr_end);
        if matches!(kind, ItemKind::ItemBody) {
            if let Some(close) = match_brace(src, term) {
                let s = line_of(&starts, attr_start);
                let e = line_of(&starts, close);
                ranges.push((s, e));
                i = close + 1;
                continue;
            }
        }
        i = attr_end;
    }
    ranges.sort();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut()
            && s <= last.1 + 1
        {
            last.1 = last.1.max(e);
            continue;
        }
        merged.push((s, e));
    }
    merged
}

#[derive(Clone, Copy)]
enum ItemKind {
    ModFile,  // `#[cfg(test)] mod NAME;`
    ItemBody, // `#[cfg(test)] mod NAME { ... }` or any other item with a body
    Unknown,
}

fn scan_item_head(src: &str, start: usize) -> (usize, ItemKind) {
    let bytes = src.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b';' {
            return (i, ItemKind::ModFile);
        }
        if b == b'{' {
            return (i, ItemKind::ItemBody);
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = i.saturating_add(2);
            continue;
        }
        if b == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i = i.saturating_add(2);
                } else {
                    i += 1;
                }
            }
            i = i.saturating_add(1);
            continue;
        }
        i += 1;
    }
    (bytes.len(), ItemKind::Unknown)
}

fn parse_mod_name(head: &str) -> Option<String> {
    let mut tokens = head.split_ascii_whitespace();
    while let Some(t) = tokens.next() {
        if t == "mod" {
            let raw = tokens.next()?.trim_end_matches(';').trim_end_matches('{');
            if !raw.is_empty() && raw.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) {
                return Some(raw.to_string());
            }
        }
    }
    None
}

fn resolve_mod_paths(parent_file: &Path, name: &str) -> Vec<PathBuf> {
    let parent_dir = parent_file.parent().unwrap_or_else(|| Path::new("."));
    let stem = parent_file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let base = if stem == "mod" || stem == "lib" || stem == "main" {
        parent_dir.to_path_buf()
    } else {
        parent_dir.join(stem)
    };
    vec![
        base.join(format!("{name}.rs")),
        base.join(name).join("mod.rs"),
    ]
}

fn match_brace(src: &str, open_pos: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    debug_assert_eq!(bytes[open_pos], b'{');
    let mut depth = 0i32;
    let mut i = open_pos;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            let mut bd = 1u32;
            while i + 1 < bytes.len() && bd > 0 {
                if bytes[i] == b'/' && bytes[i + 1] == b'*' {
                    bd += 1;
                    i += 2;
                } else if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    bd -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if b == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i = i.saturating_add(2);
                } else {
                    i += 1;
                }
            }
            i = i.saturating_add(1);
            continue;
        }
        if b == b'\'' {
            if let Some(end) = char_lit_close(bytes, i) {
                i = end + 1;
            } else {
                i += 1;
            }
            continue;
        }
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

// ----- small helpers --------------------------------------------------------

fn line_starts(src: &str) -> Vec<usize> {
    let mut v = Vec::with_capacity(src.len() / 40 + 1);
    v.push(0);
    for (i, b) in src.bytes().enumerate() {
        if b == b'\n' {
            v.push(i + 1);
        }
    }
    v
}

fn line_of(starts: &[usize], pos: usize) -> usize {
    let (mut lo, mut hi) = (0usize, starts.len() - 1);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if starts[mid] <= pos {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

// ----- output ---------------------------------------------------------------

fn print_help() {
    println!("usage: lines [--per-file|-f|--ls|-l] [PATH]   (PATH defaults to `src`)");
    println!();
    println!("Walks `.rs` files under PATH and prints a tokei-style table of");
    println!("file/line counts, with the Code column split into Impl + Test.");
    println!();
    println!("Aggregation:");
    println!("  default       one row per top-level subdirectory under PATH;");
    println!("                files directly in PATH go in a `.` row");
    println!("  --ls, -l      one row per entry directly under PATH:");
    println!("                top-level files individually, subdirs aggregated");
    println!("  --per-file    one row per `.rs` file, fully recursive");
    println!();
    println!("Test classification:");
    println!("  - lines inside `#[cfg(test)]` item bodies (brace-balanced)");
    println!("  - all lines in files declared from a parent module via");
    println!("    `#[cfg(test)] mod NAME;`");
    println!("  - all lines under a Cargo crate's `tests/` or `benches/` dir");
    println!();
    println!("Skipped during recursion: `target/`, dot-directories like `.git`.");
}

fn print_per_file(root: &Path, rows: &[(PathBuf, Counts)], total: Counts) {
    // Pick a path-column width that fits the longest path under the root.
    let mut path_w = "File (under …)".len() + root.display().to_string().len();
    for (p, _) in rows {
        path_w = path_w.max(display_rel(p, root).len());
    }
    path_w = path_w.clamp(28, 64);

    let bar_w = path_w + 1 + 9 + 1 + 9 + 1 + 9 + 1 + 9 + 1 + 9 + 1 + 7 + 2;
    let bar = "=".repeat(bar_w);
    println!("{bar}");
    println!(" Lines = Code + Comments + Blanks    |    Code = Impl + Test");
    println!("{bar}");
    let header_path = format!("File (under {})", root.display());
    println!(
        " {:<pw$} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
        header_path,
        "Lines",
        "Code",
        "Impl",
        "Test",
        "Comments",
        "Blanks",
        pw = path_w,
    );
    println!("{bar}");
    for (p, c) in rows {
        println!(
            " {:<pw$} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
            display_rel(p, root),
            c.lines,
            c.code(),
            c.code_impl,
            c.code_test,
            c.comments,
            c.blanks,
            pw = path_w,
        );
    }
    println!("{bar}");
    println!(
        " {:<pw$} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
        format!("Total ({} files)", total.files),
        total.lines,
        total.code(),
        total.code_impl,
        total.code_test,
        total.comments,
        total.blanks,
        pw = path_w,
    );
    println!("{bar}");
    print_summary_footer(total);
}

fn print_ls(root: &Path, rows: &[(PathBuf, Counts)], total: Counts) {
    // Group every file by its first-level entry under `root`. Top-level files
    // end up as their own entry (filename); files deeper in a subdir all
    // collapse onto that subdir's entry, recursively.
    use std::ffi::OsString;
    let mut entries: BTreeMap<OsString, (bool, Counts)> = BTreeMap::new();
    for (path, counts) in rows {
        let rel = path.strip_prefix(root).unwrap_or(path);
        let mut comps = rel.components();
        let Some(first) = comps.next() else { continue };
        let is_top_file = comps.next().is_none();
        let key = first.as_os_str().to_owned();
        let entry = entries
            .entry(key)
            .or_insert((is_top_file, Counts::default()));
        entry.1.add(*counts);
    }

    let display_entries: Vec<(String, Counts)> = entries
        .into_iter()
        .map(|(name, (is_file, c))| {
            let s = name.to_string_lossy().into_owned();
            (if is_file { s } else { format!("{s}/") }, c)
        })
        .collect();

    let mut path_w = "Entry (under …)".len() + root.display().to_string().len();
    for (n, _) in &display_entries {
        path_w = path_w.max(n.len());
    }
    path_w = path_w.clamp(28, 64);

    let bar_w = path_w + 1 + 7 + 1 + 9 + 1 + 9 + 1 + 9 + 1 + 9 + 1 + 9 + 1 + 7 + 2;
    let bar = "=".repeat(bar_w);
    println!("{bar}");
    println!(" Lines = Code + Comments + Blanks    |    Code = Impl + Test");
    println!("{bar}");
    let header_path = format!("Entry (under {})", root.display());
    println!(
        " {:<pw$} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
        header_path,
        "Files",
        "Lines",
        "Code",
        "Impl",
        "Test",
        "Comments",
        "Blanks",
        pw = path_w,
    );
    println!("{bar}");
    for (name, c) in &display_entries {
        println!(
            " {:<pw$} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
            name,
            c.files,
            c.lines,
            c.code(),
            c.code_impl,
            c.code_test,
            c.comments,
            c.blanks,
            pw = path_w,
        );
    }
    println!("{bar}");
    println!(
        " {:<pw$} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
        "Total",
        total.files,
        total.lines,
        total.code(),
        total.code_impl,
        total.code_test,
        total.comments,
        total.blanks,
        pw = path_w,
    );
    println!("{bar}");
    print_summary_footer(total);
}

fn print_summary_footer(total: Counts) {
    let code = total.code();
    if code > 0 && total.lines > 0 {
        let pct_total = 100.0 * total.code_test as f64 / total.lines as f64;
        let pct_code = 100.0 * total.code_test as f64 / code as f64;
        let test_to_impl = total.code_test as f64 / total.code_impl.max(1) as f64;
        println!(
            " test code: {:.1}% of all lines ({} / {})",
            pct_total,
            with_thousands(total.code_test),
            with_thousands(total.lines),
        );
        println!(
            "            {:.1}% of code lines ({} / {}; \"code\" excludes comments + blanks)",
            pct_code,
            with_thousands(total.code_test),
            with_thousands(code),
        );
        println!("            {:.2}× impl code", test_to_impl);
    }
}

fn print_table(root: &Path, by_dir: &BTreeMap<PathBuf, Counts>, total: Counts) {
    let header_path = format!("Path (under {})", root.display());
    let bar = "=".repeat(96);
    println!("{bar}");
    println!(" Lines = Code + Comments + Blanks    |    Code = Impl + Test");
    println!("{bar}");
    println!(
        " {:<28} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
        header_path, "Files", "Lines", "Code", "Impl", "Test", "Comments", "Blanks",
    );
    println!("{bar}");
    for (dir, c) in by_dir {
        println!(
            " {:<28} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
            display_rel(dir, root),
            c.files,
            c.lines,
            c.code(),
            c.code_impl,
            c.code_test,
            c.comments,
            c.blanks,
        );
    }
    println!("{bar}");
    println!(
        " {:<28} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
        "Total",
        total.files,
        total.lines,
        total.code(),
        total.code_impl,
        total.code_test,
        total.comments,
        total.blanks,
    );
    println!("{bar}");
    print_summary_footer(total);
}

fn with_thousands(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let len = bytes.len();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn display_rel(p: &Path, root: &Path) -> String {
    match p.strip_prefix(root) {
        Ok(r) => {
            let s = r.display().to_string();
            if s.is_empty() { ".".to_string() } else { s }
        }
        Err(_) => p.display().to_string(),
    }
}

// ----- tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_blank_comment_code() {
        let src = "\nfn x() {} // ok\n   \n// only\n/* block */\nlet s = \"//not\";\n";
        let k = classify_lines(src);
        assert_eq!(k.len(), 6);
        assert_eq!(k[0], LineKind::Blank);
        assert_eq!(k[1], LineKind::Code); // code with trailing comment
        assert_eq!(k[2], LineKind::Blank);
        assert_eq!(k[3], LineKind::Comment);
        assert_eq!(k[4], LineKind::Comment);
        assert_eq!(k[5], LineKind::Code); // string contains `//` but it's not a comment
    }

    #[test]
    fn block_comment_spans_lines() {
        let src = "fn a() {}\n/* line1\n   line2 */\nfn b() {}\n";
        let k = classify_lines(src);
        assert_eq!(k.len(), 4);
        assert_eq!(k[0], LineKind::Code);
        assert_eq!(k[1], LineKind::Comment);
        assert_eq!(k[2], LineKind::Comment);
        assert_eq!(k[3], LineKind::Code);
    }

    #[test]
    fn raw_string_does_not_open_comment() {
        let src = "let s = r#\"//not a comment\"#;\n";
        let k = classify_lines(src);
        assert_eq!(k, vec![LineKind::Code]);
    }

    #[test]
    fn cfg_test_block_lines_detected() {
        let src = "fn a() {}\n#[cfg(test)]\nmod t {\n    #[test]\n    fn b() {}\n}\nfn c() {}\n";
        let r = find_cfg_test_line_ranges(src);
        // Lines 1..=5 (0-indexed) cover the attribute through the closing brace.
        assert_eq!(r, vec![(1, 5)]);
    }

    #[test]
    fn cfg_test_mod_file_decl_recognized_not_inline() {
        let src = "#[cfg(test)] mod sim;\n#[cfg(test)] mod tests { fn t() {} }\n";
        let names = find_test_only_mod_decls(src);
        assert_eq!(names, vec!["sim".to_string()]);
        // The inline tests block contributes a line range, the file decl does not.
        let r = find_cfg_test_line_ranges(src);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0, 1);
    }

    #[test]
    fn brace_in_char_literal_does_not_unbalance() {
        // The `'{'` and `'}'` char literals must not perturb the brace matcher.
        let src = "#[cfg(test)]\nmod t {\n    fn f() { let _ = '{'; let _ = '}'; }\n}\nfn g() {}\n";
        let r = find_cfg_test_line_ranges(src);
        assert_eq!(r, vec![(0, 3)]);
    }

    #[test]
    fn lifetime_is_not_char_literal() {
        // `'a` (lifetime) should not break scanning.
        let src = "#[cfg(test)]\nmod t {\n    fn f<'a>(x: &'a str) -> &'a str { x }\n}\n";
        let r = find_cfg_test_line_ranges(src);
        assert_eq!(r, vec![(0, 3)]);
    }

    #[test]
    fn classify_file_splits_impl_and_test_code() {
        let src =
            "fn a() { let x = 1; }\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn b() {}\n}\n";
        let c = classify_file(src, false);
        assert_eq!(c.files, 1);
        assert_eq!(c.lines, 6);
        assert_eq!(c.code_impl, 1); // line 0
        // code lines inside the cfg(test) block: lines 1..=5 are 5 lines, but
        // line 1 (`#[cfg(test)]`) is code, line 2 (`mod tests {`) is code, line 3 (`#[test]`) is code,
        // line 4 (`fn b() {}`) is code, line 5 (`}`) is code → 5 code lines.
        assert_eq!(c.code_test, 5);
        assert_eq!(c.comments, 0);
        assert_eq!(c.blanks, 0);
    }

    #[test]
    fn whole_file_test_only_marks_all_code_as_test() {
        let src = "// header\nfn a() {}\nfn b() {}\n";
        let c = classify_file(src, true);
        assert_eq!(c.code_impl, 0);
        assert_eq!(c.code_test, 2);
        assert_eq!(c.comments, 1);
    }
}
