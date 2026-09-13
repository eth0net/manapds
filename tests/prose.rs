//! Holds the repo to one owner per fact: `docs/` explains, a comment states
//! what the code can't, and neither repeats the other. Duplicated paragraphs
//! drift apart silently and duplicated figures go stale.
//!
//! A test rather than a script, so enforcing the rule needs no toolchain the
//! repo doesn't already have.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

/// Eight words. Six catches ordinary domain phrasing; ten misses a restated
/// sentence that changed a word.
const RUN: usize = 8;

/// Condensed by design, so these are allowed to repeat `docs/`. A comment
/// still can't restate them.
const SUMMARY: [&str; 4] = ["AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "README.md"];

#[test]
fn no_prose_is_said_twice() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut failures = Vec::new();
    // Where each phrase was first seen, so a match names the file to cut
    // against.
    let mut seen: HashMap<String, String> = HashMap::new();

    let mut docs = markdown(&root);
    docs.sort();

    for path in &docs {
        let name = relative(&root, path);
        let list = words(&fs::read_to_string(path).unwrap());

        if !is_summary(path) {
            for (from, text) in spans(&list, |run| match seen.get(run) {
                Some(held) if *held != name && !SUMMARY.contains(&held.as_str()) => {
                    Some(held.clone())
                }
                _ => None,
            }) {
                failures.push(format!("{name} repeats {from}: \"{text}\""));
            }
        }

        for run in runs(&list) {
            seen.entry(run).or_insert_with(|| name.clone());
        }
    }

    let mut sources = rust(&root);
    sources.sort();

    for path in &sources {
        let name = relative(&root, path);
        for (line, block) in comments(&fs::read_to_string(path).unwrap()) {
            for (from, text) in spans(&words(&block), |run| seen.get(run).cloned()) {
                failures.push(format!("{name}:{line} repeats {from}: \"{text}\""));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "prose said twice:\n  {}",
        failures.join("\n  ")
    );
}

fn is_summary(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| SUMMARY.contains(&name))
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn markdown(root: &Path) -> Vec<PathBuf> {
    let mut found = files(root, "md", false);
    found.extend(files(&root.join("docs"), "md", true));
    found
}

fn rust(root: &Path) -> Vec<PathBuf> {
    let mut found = files(&root.join("src"), "rs", true);
    found.extend(files(&root.join("tests"), "rs", true));
    found
}

fn files(directory: &Path, extension: &str, recurse: bool) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if recurse {
                found.extend(files(&path, extension, recurse));
            }
        } else if path.extension().is_some_and(|found| found == extension) {
            found.push(path);
        }
    }
    found
}

/// Punctuation and code drop out, so a phrase matches however it was wrapped,
/// quoted or backticked.
fn words(text: &str) -> Vec<String> {
    let mut prose = String::new();
    let mut fenced = false;

    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        // Odd-numbered pieces sat between backticks.
        for (at, piece) in line.split('`').enumerate() {
            if at % 2 == 0 {
                prose.push_str(piece);
                prose.push(' ');
            }
        }
    }

    prose
        .to_lowercase()
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

fn runs(list: &[String]) -> Vec<String> {
    list.windows(RUN).map(|window| window.join(" ")).collect()
}

/// Overlapping runs describe one passage, so matches merge into spans and each
/// passage is reported once.
fn spans(list: &[String], mut source: impl FnMut(&str) -> Option<String>) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut from: Option<String> = None;
    let mut start = 0;
    let mut end = 0;

    for (at, run) in runs(list).into_iter().enumerate() {
        let Some(held) = source(&run) else { continue };

        if from.as_ref() != Some(&held) || at > end {
            if let Some(previous) = from.take() {
                found.push((previous, list[start..end].join(" ")));
            }
            from = Some(held);
            start = at;
        }
        end = at + RUN;
    }

    if let Some(previous) = from {
        found.push((previous, list[start..end].join(" ")));
    }
    found
}

/// A comment block is a run of adjacent comment lines, reported by where it
/// starts. Only `//` forms, the repo having no others.
fn comments(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut block: Vec<&str> = Vec::new();
    let mut start = 0;

    for (at, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("//") {
            if block.is_empty() {
                start = at + 1;
            }
            block.push(rest.trim_start_matches(['/', '!']).trim());
        } else if !block.is_empty() {
            found.push((start, block.join(" ")));
            block.clear();
        }
    }
    if !block.is_empty() {
        found.push((start, block.join(" ")));
    }
    found
}
