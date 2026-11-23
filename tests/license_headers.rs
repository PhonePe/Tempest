// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Every tracked source, configuration, and document file starts with the
//! project's SPDX copyright and license header; the full license text is in
//! `LICENSE`. `make license-check` runs this test and `make license-format`
//! adds missing headers in place.

use std::path::Path;
use std::process::Command;
use std::{env, fs};

const HEADER: [&str; 2] = [
    "SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.",
    "SPDX-License-Identifier: Apache-2.0",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Style {
    /// `//` line comments: Rust.
    Slash,
    /// `#` line comments: Python, shell, YAML, TOML, Make, Docker, Salt.
    Hash,
    /// `!` line comments: FRR configuration.
    Bang,
    /// `<!-- ... -->` per line: Markdown.
    Html,
    /// `{#- ... -#}` per line: Jinja templates, so rendered files stay unchanged.
    Jinja,
}

#[derive(Debug, PartialEq, Eq)]
enum Rule {
    Header(Style),
    /// Formats without comments (JSON, lockfiles), license texts, generated
    /// or fixture files, and contributor-facing templates.
    Exempt,
}

fn rule_for(path: &str) -> Option<Rule> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let exempt_path = matches!(
        path,
        "CHANGELOG.md" | "src/api/metrics/schema.txt" | ".github/pull_request_template.md"
    ) || path.contains("/merge_request_templates/");
    let exempt_name = name.starts_with("LICENSE")
        || name == "NOTICE"
        || name.ends_with(".lock")
        || name.ends_with(".json")
        || matches!(
            name,
            ".gitignore" | ".dockerignore" | ".containerignore" | ".gitkeep"
        );
    if exempt_path || exempt_name {
        return Some(Rule::Exempt);
    }

    const HASH_SUFFIXES: [&str; 9] = [
        ".py",
        ".sh",
        ".yml",
        ".yaml",
        ".toml",
        ".properties",
        ".sls",
        ".example",
        ".service",
    ];
    let style = if name.ends_with(".rs") {
        Style::Slash
    } else if name.ends_with(".md") {
        Style::Html
    } else if name.ends_with(".jinja") {
        Style::Jinja
    } else if path.contains("/frr/") && name.ends_with(".conf.example") {
        Style::Bang
    } else if matches!(
        name,
        "Makefile" | "Dockerfile" | "Containerfile" | ".editorconfig" | ".gitattributes"
    ) || HASH_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
    {
        Style::Hash
    } else {
        return None;
    };
    Some(Rule::Header(style))
}

fn render(style: Style) -> String {
    let (open, close) = match style {
        Style::Slash => ("// ", ""),
        Style::Hash => ("# ", ""),
        Style::Bang => ("! ", ""),
        Style::Html => ("<!-- ", " -->"),
        Style::Jinja => ("{#- ", " -#}"),
    };
    let mut out: String = HEADER
        .iter()
        .map(|line| format!("{open}{line}{close}\n"))
        .collect();
    // Jinja's `-#}` already strips the following newline.
    if style != Style::Jinja {
        out.push('\n');
    }
    out
}

/// Splits off a first line that must stay first: a shebang or a Dockerfile
/// parser directive.
fn split_prefix(content: &str) -> (&str, &str) {
    if content.starts_with("#!") || content.starts_with("# syntax=") {
        let end = content.find('\n').map_or(content.len(), |index| index + 1);
        content.split_at(end)
    } else {
        ("", content)
    }
}

fn with_header(content: &str, style: Style) -> Option<String> {
    let header = render(style);
    let (prefix, body) = split_prefix(content);
    if body.starts_with(&header) {
        return None;
    }
    Some(format!("{prefix}{header}{body}"))
}

#[test]
fn tracked_files_carry_the_license_header() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    if !root.join(".git").exists() {
        eprintln!("skipping license header check: not a git checkout");
        return;
    }
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .expect("run git ls-files");
    assert!(output.status.success(), "git ls-files failed");

    let format = env::var_os("TEMPEST_LICENSE_FORMAT").is_some();
    let mut unclassified = Vec::new();
    let mut missing = Vec::new();
    for raw in output.stdout.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let path = std::str::from_utf8(raw).expect("UTF-8 tracked path");
        let style = match rule_for(path) {
            None => {
                unclassified.push(path.to_owned());
                continue;
            }
            Some(Rule::Exempt) => continue,
            Some(Rule::Header(style)) => style,
        };
        let file = root.join(path);
        if !file.exists() {
            continue;
        }
        let content = fs::read_to_string(&file).expect("read tracked text file");
        let Some(updated) = with_header(&content, style) else {
            continue;
        };
        if format {
            fs::write(&file, updated).expect("write license header");
        } else {
            missing.push(path.to_owned());
        }
    }

    assert!(
        unclassified.is_empty(),
        "no license header rule for {unclassified:?}; add one to tests/license_headers.rs"
    );
    assert!(
        missing.is_empty(),
        "missing or outdated license header in {missing:?}; run `make license-format`"
    );
}

#[test]
fn header_follows_shebang() {
    let script = "#!/usr/bin/env bash\nset -eu\n";
    let updated = with_header(script, Style::Hash).expect("header added");
    assert_eq!(
        updated,
        "#!/usr/bin/env bash\n\
         # SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.\n\
         # SPDX-License-Identifier: Apache-2.0\n\nset -eu\n"
    );
    assert_eq!(with_header(&updated, Style::Hash), None);
}

#[test]
fn jinja_header_renders_to_nothing() {
    let header = render(Style::Jinja);
    assert!(
        header
            .lines()
            .all(|line| line.starts_with("{#- ") && line.ends_with(" -#}"))
    );
}

#[test]
fn every_rule_is_explicit() {
    assert_eq!(rule_for("src/main.rs"), Some(Rule::Header(Style::Slash)));
    assert_eq!(rule_for("README.md"), Some(Rule::Header(Style::Html)));
    assert_eq!(rule_for("CHANGELOG.md"), Some(Rule::Exempt));
    assert_eq!(
        rule_for("deploy/container/frr/frr-odd.conf.example"),
        Some(Rule::Header(Style::Bang))
    );
    assert_eq!(
        rule_for("grafana/tempest-dashboard.json"),
        Some(Rule::Exempt)
    );
    assert_eq!(rule_for("unknown.xyz"), None);
}
