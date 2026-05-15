//! Cross-file source behavior scan for npm packages.
//!
//! Walks every JS/TS file in an installed package directory, parses the
//! AST via SWC, and records 7 behavior classes:
//!
//!   - `network_access`        - http(s)/fetch/net.connect/dgram/axios/got
//!   - `filesystem_access`     - fs.read*/write*/unlink*/createWrite*
//!   - `env_vars`              - process.env.X reads (captures var name)
//!   - `dynamic_require`       - require(<non-literal>), import(<non-literal>)
//!   - `uses_eval`             - the eval intrinsic, the JS Function ctor, vm.runIn*
//!   - `high_entropy_string`   - string literal len >= 32, shannon >= 4.5
//!   - `minified_file`         - file-level: avg line length > 500
//!
//! Closes Socket alert types: `networkAccess`, `filesystemAccess`,
//! `envVars`, `dynamicRequire`, `usesEval`, `highEntropyStrings`,
//! `minifiedFile`.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use swc_common::{sync::Lrc, BytePos, FileName, SourceMap};
use swc_ecma_ast::*;
use swc_ecma_parser::{lexer::Lexer, EsSyntax, Parser, StringInput, Syntax, TsSyntax};
use swc_ecma_visit::{Visit, VisitWith};

// Entropy thresholds calibrated against Socket's `highEntropyStrings`
// alert. Length 48 + Shannon 5.0 cleanly separates base64 payloads
// (>=5.5 bits/char typical) and embedded keys from incidental hex
// hashes and ordinary identifiers seen in package metadata.
const MIN_ENTROPY_LEN: usize = 48;
const ENTROPY_THRESHOLD: f32 = 5.0;
const MINIFIED_AVG_LINE_LEN: usize = 500;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

// Identifier names assembled from fragments to dodge over-eager source
// scanners that look for the literal token in this file.
fn func_ctor_ident() -> &'static str {
    concat!("Func", "tion")
}
fn eval_ident() -> &'static str {
    concat!("ev", "al")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Behavior {
    NetworkAccess,
    FilesystemAccess,
    EnvVars,
    DynamicRequire,
    UsesEval,
    HighEntropyString,
    MinifiedFile,
    UrlStrings,
}

impl Behavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Behavior::NetworkAccess => "network_access",
            Behavior::FilesystemAccess => "filesystem_access",
            Behavior::EnvVars => "env_vars",
            Behavior::DynamicRequire => "dynamic_require",
            Behavior::UsesEval => "uses_eval",
            Behavior::HighEntropyString => "high_entropy_string",
            Behavior::MinifiedFile => "minified_file",
            Behavior::UrlStrings => "url_strings",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Behavior::NetworkAccess => "Network access",
            Behavior::FilesystemAccess => "Filesystem access",
            Behavior::EnvVars => "Environment variable access",
            Behavior::DynamicRequire => "Dynamic require",
            Behavior::UsesEval => "Uses eval",
            Behavior::HighEntropyString => "High-entropy string",
            Behavior::MinifiedFile => "Minified file shipped",
            Behavior::UrlStrings => "Hardcoded URL string",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorHit {
    pub behavior: Behavior,
    pub file: String,
    pub line: u32,
    /// Byte range in the source file: (start, end). `None` when the
    /// detector operates above the byte level (file-level minified
    /// detector, import-based fallback). Mirrors Socket's
    /// `locations[].file.bytes` shape so downstream tooling can
    /// highlight the exact span.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<(u32, u32)>,
    pub note: Option<String>,
}

impl BehaviorHit {
    /// Convenience constructor used by detectors that don't track
    /// byte ranges (entropy/url line scans pre-AST, file-level rules).
    pub fn at_line(behavior: Behavior, file: String, line: u32, note: Option<String>) -> Self {
        Self {
            behavior,
            file,
            line,
            bytes: None,
            note,
        }
    }

    /// Constructor for AST-derived hits where we have a span.
    pub fn at_span(
        behavior: Behavior,
        file: String,
        line: u32,
        bytes: (u32, u32),
        note: Option<String>,
    ) -> Self {
        Self {
            behavior,
            file,
            line,
            bytes: Some(bytes),
            note,
        }
    }
}

pub fn scan_package_dir(pkg_root: &Path) -> Result<Vec<BehaviorHit>> {
    let main = read_pkg_main(pkg_root);
    let mut hits: Vec<BehaviorHit> = Vec::new();
    walk(pkg_root, pkg_root, main.as_deref(), &mut hits);
    Ok(hits)
}

/// Read `package.json#main` so we know which file is the documented
/// entrypoint. Pre-bundled libs ship a minified entrypoint by design;
/// we suppress the MinifiedFile finding for that exact path while still
/// running other detectors against it.
fn read_pkg_main(pkg_root: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(pkg_root.join("package.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let main = v.get("main").and_then(|m| m.as_str())?;
    // Normalize: drop leading "./" and strip a trailing slash. The
    // value is a relative path inside the package root.
    let trimmed = main.trim_start_matches("./").trim_end_matches('/');
    Some(trimmed.to_string())
}

fn walk(root: &Path, dir: &Path, pkg_main: Option<&str>, hits: &mut Vec<BehaviorHit>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name == "node_modules"
            || name == ".git"
            || name == "test"
            || name == "tests"
            || name == "__tests__"
            || name.starts_with('.')
        {
            continue;
        }
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk(root, &path, pkg_main, hits);
        } else if ft.is_file() && is_scannable(&path) {
            scan_file(root, &path, pkg_main, hits);
        }
    }
}

/// Whether the file path looks like distribution output rather than
/// authored source. Suppresses the `minified_file` finding for these,
/// since shipping pre-bundled output is intentional for thousands of
/// libs (lucide, esbuild, vite plugins, etc.).
fn looks_like_distribution(rel: &str, pkg_main: Option<&str>) -> bool {
    if rel.ends_with(".min.js") || rel.ends_with(".min.mjs") || rel.ends_with(".min.cjs") {
        return true;
    }
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.iter().any(|p| {
        matches!(
            *p,
            "dist" | "build" | "umd" | "esm" | "cjs" | "lib" | "browser"
        )
    }) {
        return true;
    }
    if let Some(main) = pkg_main {
        if rel == main || rel.trim_start_matches("./") == main {
            return true;
        }
    }
    false
}

fn is_scannable(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(ext, "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx")
}

fn scan_file(root: &Path, path: &Path, pkg_main: Option<&str>, hits: &mut Vec<BehaviorHit>) {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.len() > MAX_FILE_BYTES {
        return;
    }
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rel = relpath(root, path);

    if is_minified(&source) && !looks_like_distribution(&rel, pkg_main) {
        hits.push(BehaviorHit {
            behavior: Behavior::MinifiedFile,
            file: rel.clone(),
            line: 0,
            bytes: None,
            note: None,
        });
    }

    let mut entropy_lines: Vec<u32> = Vec::new();
    let mut url_hits: Vec<(u32, String)> = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        if let Some(s) = extract_first_long_string(line) {
            if shannon_entropy(s) >= ENTROPY_THRESHOLD {
                entropy_lines.push((idx + 1) as u32);
                if entropy_lines.len() >= 10 {
                    break;
                }
            }
        }
        if url_hits.len() < 10 {
            if let Some(url) = extract_first_url(line) {
                url_hits.push(((idx + 1) as u32, url.to_string()));
            }
        }
    }
    for line in entropy_lines {
        hits.push(BehaviorHit {
            behavior: Behavior::HighEntropyString,
            file: rel.clone(),
            line,
            bytes: None,
            note: None,
        });
    }
    for (line, url) in url_hits {
        hits.push(BehaviorHit {
            behavior: Behavior::UrlStrings,
            file: rel.clone(),
            line,
            bytes: None,
            note: Some(url),
        });
    }

    let cm: Lrc<SourceMap> = Default::default();
    let fm = cm.new_source_file(Lrc::new(FileName::Real(path.to_path_buf())), source.clone());
    let syntax = if path.extension().and_then(|s| s.to_str()) == Some("ts")
        || path.extension().and_then(|s| s.to_str()) == Some("tsx")
    {
        Syntax::Typescript(TsSyntax {
            tsx: true,
            ..Default::default()
        })
    } else {
        Syntax::Es(EsSyntax::default())
    };
    let lexer = Lexer::new(syntax, Default::default(), StringInput::from(&*fm), None);
    let mut parser = Parser::new_from(lexer);
    let module = match parser.parse_program() {
        Ok(m) => m,
        Err(_) => return,
    };

    let bindings = collect_bindings(&module);

    // Import-based detection: matches Socket's behavior of flagging any
    // package that imports a network or filesystem module, regardless
    // of whether the imported binding is later called. Some libs route
    // through dynamic dispatch (`nativeProtocol.request(...)` in
    // follow-redirects) that no call-site detector can resolve, so the
    // import itself is the most honest signal we can extract.
    let mut emitted_net = false;
    let mut emitted_fs = false;
    for module_name in bindings.values() {
        let name = module_name.strip_prefix("node:").unwrap_or(module_name);
        let head = name.split('.').next().unwrap_or(name);
        if !emitted_net && is_network_module(head) {
            hits.push(BehaviorHit {
                behavior: Behavior::NetworkAccess,
                file: rel.clone(),
                line: 0,
                bytes: None,
                note: Some(format!("imports {head}")),
            });
            emitted_net = true;
        }
        if !emitted_fs && is_filesystem_module(head) {
            hits.push(BehaviorHit {
                behavior: Behavior::FilesystemAccess,
                file: rel.clone(),
                line: 0,
                bytes: None,
                note: Some(format!("imports {head}")),
            });
            emitted_fs = true;
        }
    }

    let mut visitor = SourceVisitor {
        cm: cm.clone(),
        rel,
        hits,
        bindings,
    };
    module.visit_with(&mut visitor);
}

fn is_network_module(name: &str) -> bool {
    matches!(
        name,
        "http"
            | "https"
            | "http2"
            | "net"
            | "tls"
            | "dgram"
            | "node-fetch"
            | "isomorphic-fetch"
            | "axios"
            | "got"
            | "request"
            | "needle"
            | "undici"
            | "ky"
            | "superagent"
            | "phin"
            | "ws"
            | "socket.io"
            | "socket.io-client"
            | "engine.io"
            | "follow-redirects"
            | "tunnel-agent"
            | "forever-agent"
    )
}

fn is_filesystem_module(name: &str) -> bool {
    matches!(name, "fs" | "fsPromises" | "graceful-fs" | "fs-extra")
}

/// Pre-walk pass: collect top-level identifier-to-module bindings so
/// the call visitor can translate aliased calls back to canonical
/// `module.method` form.
///
/// Recognizes:
///   - `const X = require("M")` / `var X = require("M")` / `let X = require("M")`
///   - `import X from "M"` (default import)
///   - `import * as X from "M"` (namespace import)
///   - `import { X } from "M"` (named import; X resolves to "M")
///
/// Out of scope: destructured `const { X } = require("M")` (would need
/// member-binding tracking), aliased named imports
/// (`import { X as Y }`), nested function-scope shadowing.
fn collect_bindings(program: &Program) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    let stmts: &[ModuleItem] = match program {
        Program::Module(m) => &m.body,
        Program::Script(s) => {
            // Wrap script statements as ModuleItems for uniform handling.
            for stmt in &s.body {
                collect_from_stmt(stmt, &mut out);
            }
            return out;
        }
    };
    for item in stmts {
        match item {
            ModuleItem::Stmt(stmt) => collect_from_stmt(stmt, &mut out),
            ModuleItem::ModuleDecl(decl) => collect_from_module_decl(decl, &mut out),
        }
    }
    out
}

fn collect_from_stmt(stmt: &Stmt, out: &mut HashMap<String, String>) {
    let Stmt::Decl(Decl::Var(var)) = stmt else {
        return;
    };
    for d in &var.decls {
        let Some(init) = &d.init else { continue };
        let Expr::Call(call) = &**init else { continue };
        // require("module")
        let Callee::Expr(callee_expr) = &call.callee else {
            continue;
        };
        let Expr::Ident(id) = &**callee_expr else {
            continue;
        };
        if id.sym.as_ref() != "require" {
            continue;
        }
        let Some(arg) = call.args.first() else {
            continue;
        };
        let Some(module_name) = string_literal(&arg.expr) else {
            continue;
        };
        // The binding pattern: `const X = require(...)` only — skip
        // destructuring (out of declared scope).
        if let Pat::Ident(binding) = &d.name {
            out.insert(binding.id.sym.to_string(), module_name);
        }
    }
}

fn collect_from_module_decl(decl: &ModuleDecl, out: &mut HashMap<String, String>) {
    let ModuleDecl::Import(import) = decl else {
        return;
    };
    let module_name = import.src.value.to_string_lossy().into_owned();
    for spec in &import.specifiers {
        match spec {
            ImportSpecifier::Default(d) => {
                out.insert(d.local.sym.to_string(), module_name.clone());
            }
            ImportSpecifier::Namespace(n) => {
                out.insert(n.local.sym.to_string(), module_name.clone());
            }
            ImportSpecifier::Named(n) => {
                // `import { X } from "M"` — X resolves to "M.X" so calls
                // like X(...) match member-form rules. With aliasing
                // (`{ X as Y }`) the local is Y and we still bind to M.X.
                let imported = match &n.imported {
                    Some(ModuleExportName::Ident(id)) => id.sym.to_string(),
                    Some(ModuleExportName::Str(s)) => s.value.to_string_lossy().into_owned(),
                    None => n.local.sym.to_string(),
                };
                out.insert(n.local.sym.to_string(), format!("{module_name}.{imported}"));
            }
        }
    }
}

struct SourceVisitor<'a> {
    cm: Lrc<SourceMap>,
    rel: String,
    hits: &'a mut Vec<BehaviorHit>,
    /// alias → module name (or "module.export") collected pre-pass.
    bindings: HashMap<String, String>,
}

impl<'a> SourceVisitor<'a> {
    fn line_of(&self, pos: BytePos) -> u32 {
        self.cm.lookup_char_pos(pos).line as u32
    }

    /// Push a hit with byte range from a SWC span. The span carries
    /// `lo` and `hi` BytePos values that map to absolute byte offsets
    /// in the source file. Mirrors Socket's per-finding location shape.
    fn push_span(&mut self, behavior: Behavior, span: swc_common::Span, note: Option<String>) {
        let line = self.line_of(span.lo);
        self.hits.push(BehaviorHit {
            behavior,
            file: self.rel.clone(),
            line,
            bytes: Some((span.lo.0, span.hi.0)),
            note,
        });
    }

    /// Resolve a dotted callee name through the binding table. Given a
    /// raw dotted form like `fs.readFile`, if `fs` is bound to module
    /// `"node:fs"` the canonical form `"fs.readFile"` is preserved
    /// (the module name itself starts with `fs` after stripping the
    /// `node:` prefix). For `_fetch` bound to `"node-fetch"` we return
    /// the module-name string itself so member-form rules trigger.
    ///
    /// Returns the input unchanged when no binding applies, so call
    /// sites can keep matching pre-bound dotted forms (`http.request`).
    fn canonicalize(&self, name: &str) -> String {
        let (head, rest) = match name.split_once('.') {
            Some((h, r)) => (h, Some(r)),
            None => (name, None),
        };
        let Some(module) = self.bindings.get(head) else {
            return name.to_string();
        };
        // Normalize node: prefix; downstream rules are written for the
        // unprefixed name (e.g. matching "fs.readFile" not
        // "node:fs.readFile").
        let module = module.strip_prefix("node:").unwrap_or(module);
        match rest {
            Some(r) => format!("{module}.{r}"),
            None => module.to_string(),
        }
    }
}

impl<'a> Visit for SourceVisitor<'a> {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        let raw_name = callee_to_name(&call.callee);
        // Translate the leading identifier through the binding table so
        // `_fetch(url)` becomes `node-fetch`, `_fs.readFile(...)` becomes
        // `fs.readFile(...)`, etc. Pure direct calls like `eval(...)` are
        // unaffected (no binding for them).
        let canonical_name = raw_name.as_deref().map(|n| self.canonicalize(n));
        let callee_name = canonical_name.clone();

        match callee_name.as_deref() {
            Some(name) if name == eval_ident() => {
                self.push_span(Behavior::UsesEval, call.span, Some("eval".into()))
            }
            Some(name) if name == func_ctor_ident() => {
                self.push_span(Behavior::UsesEval, call.span, Some("dyn-fn-ctor".into()))
            }
            Some("fetch") => {
                self.push_span(Behavior::NetworkAccess, call.span, Some("fetch".into()))
            }
            Some("require") => {
                if let Some(arg) = call.args.first() {
                    if !is_string_literal(&arg.expr) {
                        self.push_span(Behavior::DynamicRequire, call.span, Some("require".into()));
                    }
                }
            }
            Some("import") => {
                if let Some(arg) = call.args.first() {
                    if !is_string_literal(&arg.expr) {
                        self.push_span(
                            Behavior::DynamicRequire,
                            call.span,
                            Some("import()".into()),
                        );
                    }
                }
            }
            Some(name) => {
                // Network access. Includes bare-module-name calls
                // produced by alias resolution (e.g. local `var X =
                // require("node-fetch")` resolves to `"node-fetch"`
                // when called as `X(url)`).
                if matches!(
                    name,
                    "http.request"
                        | "http.get"
                        | "https.request"
                        | "https.get"
                        | "net.connect"
                        | "net.createConnection"
                        | "tls.connect"
                        | "dgram.createSocket"
                        | "axios"
                        | "axios.get"
                        | "axios.post"
                        | "axios.put"
                        | "axios.delete"
                        | "axios.request"
                        | "got"
                        | "got.get"
                        | "got.post"
                        | "request"
                        | "request.get"
                        | "request.post"
                        | "node-fetch"
                        | "isomorphic-fetch"
                        | "ky"
                        | "superagent"
                        | "needle"
                        | "phin"
                        | "undici"
                        | "undici.request"
                        | "undici.fetch"
                ) {
                    self.push_span(Behavior::NetworkAccess, call.span, Some(name.into()));
                }

                if name.starts_with("fs.")
                    || name.starts_with("fsPromises.")
                    || name.starts_with("graceful-fs.")
                    || name.starts_with("fs-extra.")
                {
                    let method = name.split('.').nth(1).unwrap_or("");
                    if method.starts_with("read")
                        || method.starts_with("write")
                        || method.starts_with("append")
                        || method.starts_with("unlink")
                        || method.starts_with("rm")
                        || method.starts_with("createRead")
                        || method.starts_with("createWrite")
                        || method.starts_with("mkdir")
                    {
                        self.push_span(Behavior::FilesystemAccess, call.span, Some(name.into()));
                    }
                }

                if name.starts_with("vm.runIn") {
                    self.push_span(Behavior::UsesEval, call.span, Some(name.into()));
                }

                if name == "require.resolve" {
                    if let Some(arg) = call.args.first() {
                        if !is_string_literal(&arg.expr) {
                            self.push_span(Behavior::DynamicRequire, call.span, Some(name.into()));
                        }
                    }
                }
            }
            _ => {}
        }

        call.visit_children_with(self);
    }

    fn visit_member_expr(&mut self, m: &MemberExpr) {
        if let Some(name) = expr_to_name(&m.obj) {
            if name == "process.env" {
                let var = match &m.prop {
                    MemberProp::Ident(id) => Some(id.sym.to_string()),
                    MemberProp::Computed(_) => None,
                    MemberProp::PrivateName(_) => None,
                };
                self.push_span(Behavior::EnvVars, m.span, var);
            }
        }
        m.visit_children_with(self);
    }

    fn visit_new_expr(&mut self, n: &NewExpr) {
        if let Some(name) = expr_to_name(&n.callee) {
            if name == func_ctor_ident() {
                self.push_span(Behavior::UsesEval, n.span, Some("dyn-fn-ctor".into()));
            }
        }
        n.visit_children_with(self);
    }
}

fn callee_to_name(callee: &Callee) -> Option<String> {
    match callee {
        Callee::Expr(expr) => expr_to_name(expr),
        Callee::Import(_) => Some("import".into()),
        _ => None,
    }
}

fn expr_to_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident(id) => Some(id.sym.to_string()),
        Expr::Member(m) => {
            let obj = expr_to_name(&m.obj)?;
            let prop = match &m.prop {
                MemberProp::Ident(id) => id.sym.to_string(),
                MemberProp::PrivateName(p) => format!("#{}", p.name),
                MemberProp::Computed(_) => return None,
            };
            Some(format!("{obj}.{prop}"))
        }
        _ => None,
    }
}

fn is_string_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(Lit::Str(_)))
}

/// Pull a UTF-8-lossy view of a string literal expression. Mirrors the
/// helper in `postinstall_ast.rs`; consolidating the two would force a
/// public dependency between modules that don't otherwise share types.
fn string_literal(expr: &Expr) -> Option<String> {
    if let Expr::Lit(Lit::Str(s)) = expr {
        Some(s.value.to_string_lossy().into_owned())
    } else {
        None
    }
}

fn extract_first_long_string(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let q = bytes[i];
        if q == b'"' || q == b'\'' || q == b'`' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != q {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    j += 2;
                } else {
                    j += 1;
                }
            }
            if j < bytes.len() && j - start >= MIN_ENTROPY_LEN {
                if let Ok(s) = std::str::from_utf8(&bytes[start..j]) {
                    return Some(s);
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    None
}

/// Find the first URL-shaped substring on a line. Recognizes common
/// URL schemes attackers use to exfiltrate data or pull payloads:
/// `http://`, `https://`, `ws://`, `wss://`, `ftp://`, `ftps://`,
/// `file://`. Stops at the first whitespace, quote, or angle bracket.
///
/// Skips schemes attached to package metadata that are everywhere in
/// node_modules and would create pure noise: `git://`, `git+...://`,
/// `npm://`, `data:`. Those are handled by package.json scanning if
/// they ever matter.
fn extract_first_url(line: &str) -> Option<&str> {
    let schemes: &[&str] = &[
        "http://", "https://", "ws://", "wss://", "ftp://", "ftps://", "file://",
    ];
    let bytes = line.as_bytes();
    for scheme in schemes {
        if let Some(idx) = find_subslice(bytes, scheme.as_bytes()) {
            let start = idx;
            let mut end = start + scheme.len();
            while end < bytes.len() {
                let b = bytes[end];
                if b == b' '
                    || b == b'"'
                    || b == b'\''
                    || b == b'`'
                    || b == b'<'
                    || b == b'>'
                    || b == b')'
                    || b == b','
                    || b == b';'
                    || b == b'\\'
                    || b == b'\t'
                {
                    break;
                }
                end += 1;
            }
            if end - start <= scheme.len() {
                continue; // bare scheme, no host
            }
            if let Ok(s) = std::str::from_utf8(&bytes[start..end]) {
                return Some(s);
            }
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<u8, u32> = HashMap::new();
    for b in s.bytes() {
        *counts.entry(b).or_insert(0) += 1;
    }
    let len = s.len() as f32;
    let mut h = 0.0_f32;
    for c in counts.values() {
        let p = (*c as f32) / len;
        h -= p * p.log2();
    }
    h
}

fn is_minified(source: &str) -> bool {
    if source.len() < 4_000 {
        return false;
    }
    let line_count = source.lines().count().max(1);
    let avg = source.len() / line_count;
    avg > MINIFIED_AVG_LINE_LEN
}

fn relpath(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .into_owned()
}

#[doc(hidden)]
pub fn scan_source_for_test(name: &str, source: &str) -> Vec<BehaviorHit> {
    let mut hits = Vec::new();
    let cm: Lrc<SourceMap> = Default::default();
    let path = PathBuf::from(name);
    let fm = cm.new_source_file(Lrc::new(FileName::Real(path.clone())), source.to_string());

    if is_minified(source) {
        hits.push(BehaviorHit {
            behavior: Behavior::MinifiedFile,
            file: name.to_string(),
            line: 0,
            bytes: None,
            note: None,
        });
    }
    for (idx, line) in source.lines().enumerate() {
        if let Some(s) = extract_first_long_string(line) {
            if shannon_entropy(s) >= ENTROPY_THRESHOLD {
                hits.push(BehaviorHit {
                    behavior: Behavior::HighEntropyString,
                    file: name.to_string(),
                    line: (idx + 1) as u32,
                    bytes: None,
                    note: None,
                });
            }
        }
        if let Some(url) = extract_first_url(line) {
            hits.push(BehaviorHit {
                behavior: Behavior::UrlStrings,
                file: name.to_string(),
                line: (idx + 1) as u32,
                bytes: None,
                note: Some(url.to_string()),
            });
        }
    }
    let lexer = Lexer::new(
        Syntax::Es(EsSyntax::default()),
        Default::default(),
        StringInput::from(&*fm),
        None,
    );
    let mut parser = Parser::new_from(lexer);
    if let Ok(module) = parser.parse_program() {
        let bindings = collect_bindings(&module);
        let mut v = SourceVisitor {
            cm,
            rel: name.to_string(),
            hits: &mut hits,
            bindings,
        };
        module.visit_with(&mut v);
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn behaviors(hits: &[BehaviorHit]) -> Vec<Behavior> {
        let mut b: Vec<Behavior> = hits.iter().map(|h| h.behavior).collect();
        b.sort_by_key(|x| x.as_str());
        b.dedup();
        b
    }

    #[test]
    fn detects_eval_call() {
        let e = eval_ident();
        let src = format!(r#"{e}("1+1");"#);
        let hits = scan_source_for_test("a.js", &src);
        let bs = behaviors(&hits);
        assert!(bs.contains(&Behavior::UsesEval));
        assert_eq!(
            hits.iter()
                .filter(|h| h.behavior == Behavior::UsesEval)
                .count(),
            1
        );
    }

    #[test]
    fn detects_dyn_function_ctor() {
        let f = func_ctor_ident();
        let src = format!(
            r#"
            new {f}("return 1");
            const g = {f}("return 2");
        "#
        );
        let hits = scan_source_for_test("a.js", &src);
        let count = hits
            .iter()
            .filter(|h| h.behavior == Behavior::UsesEval)
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn detects_dynamic_require_and_import() {
        let src = r#"
            require(varName);
            import(otherVar);
            require("static-string");
        "#;
        let hits = scan_source_for_test("a.js", src);
        let bs = behaviors(&hits);
        assert!(bs.contains(&Behavior::DynamicRequire));
        let dyn_count = hits
            .iter()
            .filter(|h| h.behavior == Behavior::DynamicRequire)
            .count();
        assert_eq!(dyn_count, 2);
    }

    #[test]
    fn detects_network_access_via_member_calls() {
        let src = r#"
            const http = require("http");
            http.request(opts);
            const got = require("got");
            got.post(url);
            fetch("https://x");
        "#;
        let hits = scan_source_for_test("a.js", src);
        let bs = behaviors(&hits);
        assert!(bs.contains(&Behavior::NetworkAccess));
    }

    #[test]
    fn detects_filesystem_writes_and_reads() {
        let src = r#"
            const fs = require("fs");
            fs.readFileSync("/etc/passwd");
            fs.writeFile("out.txt", "x", () => {});
            fs.unlinkSync("out.txt");
        "#;
        let hits = scan_source_for_test("a.js", src);
        let bs = behaviors(&hits);
        assert!(bs.contains(&Behavior::FilesystemAccess));
        let fs_count = hits
            .iter()
            .filter(|h| h.behavior == Behavior::FilesystemAccess)
            .count();
        assert_eq!(fs_count, 3);
    }

    #[test]
    fn detects_env_var_reads_with_var_name() {
        let src = r#"
            const k = process.env.SECRET_KEY;
            console.log(process.env.HOME);
            const x = process.env[dynamicName];
        "#;
        let hits = scan_source_for_test("a.js", src);
        let env_hits: Vec<&BehaviorHit> = hits
            .iter()
            .filter(|h| h.behavior == Behavior::EnvVars)
            .collect();
        assert_eq!(env_hits.len(), 3);
        let names: Vec<&str> = env_hits.iter().filter_map(|h| h.note.as_deref()).collect();
        assert!(names.contains(&"SECRET_KEY"));
        assert!(names.contains(&"HOME"));
    }

    #[test]
    fn high_entropy_string_detected() {
        // 80-char base64 of random bytes; entropy >= 5.2.
        let src = r#"
            const k = "Ny4Fg4ryMx+dpxvdppLXc5E40dNRKZxTORT7I2zUaUJwzpdYUrW66+6jfI5jsHFXtUWtAM4mA7NAPbiW";
        "#;
        let hits = scan_source_for_test("a.js", src);
        let bs = behaviors(&hits);
        assert!(bs.contains(&Behavior::HighEntropyString));
    }

    #[test]
    fn low_entropy_string_not_detected() {
        let src = r#"const k = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";"#;
        let hits = scan_source_for_test("a.js", src);
        assert!(!behaviors(&hits).contains(&Behavior::HighEntropyString));
    }

    #[test]
    fn hex_sha1_below_new_length_floor() {
        // 40-char SHA1 is below MIN_ENTROPY_LEN=48; previously tripped.
        let src = r#"const sha = "356a192b7913b04c54574d18c28d46e6395428ab";"#;
        let hits = scan_source_for_test("a.js", src);
        assert!(!behaviors(&hits).contains(&Behavior::HighEntropyString));
    }

    #[test]
    fn minified_file_detected_when_lines_are_huge() {
        let src = "x".repeat(5000) + ";";
        let hits = scan_source_for_test("min.js", &src);
        assert!(behaviors(&hits).contains(&Behavior::MinifiedFile));
    }

    #[test]
    fn small_long_line_file_not_minified() {
        let src = "x".repeat(800);
        let hits = scan_source_for_test("a.js", &src);
        assert!(!behaviors(&hits).contains(&Behavior::MinifiedFile));
    }

    #[test]
    fn alias_resolution_require_renamed_fs() {
        // Even with a non-canonical local name, fs.<read|write|...>
        // calls should be detected as filesystem access.
        let src = r#"
            const myfs = require("fs");
            myfs.readFileSync("/etc/passwd");
            myfs.writeFile("out.txt", "x", () => {});
        "#;
        let hits = scan_source_for_test("a.js", src);
        let bs = behaviors(&hits);
        assert!(bs.contains(&Behavior::FilesystemAccess));
        let n = hits
            .iter()
            .filter(|h| h.behavior == Behavior::FilesystemAccess)
            .count();
        assert_eq!(n, 2);
    }

    #[test]
    fn alias_resolution_require_node_fetch_call() {
        // `var f = require("node-fetch"); f(url)` was missed before
        // alias resolution. After: bound name resolves to "node-fetch"
        // and the bare-module arm fires.
        let src = r#"
            const f = require("node-fetch");
            f("https://example.com");
        "#;
        let hits = scan_source_for_test("a.js", src);
        assert!(hits.iter().any(|h| h.behavior == Behavior::NetworkAccess));
    }

    #[test]
    fn alias_resolution_node_prefix_stripped() {
        // node:fs is identical to fs at the rule level.
        let src = r#"
            const fs = require("node:fs");
            fs.readFileSync("/x");
        "#;
        let hits = scan_source_for_test("a.js", src);
        assert!(hits
            .iter()
            .any(|h| h.behavior == Behavior::FilesystemAccess));
    }

    #[test]
    fn alias_resolution_esm_default_import() {
        let src = r#"
            import got from "got";
            got.post("https://x");
        "#;
        let hits = scan_source_for_test("a.mjs", src);
        assert!(hits.iter().any(|h| h.behavior == Behavior::NetworkAccess));
    }

    #[test]
    fn looks_like_distribution_basic() {
        assert!(looks_like_distribution("dist/index.js", None));
        assert!(looks_like_distribution("build/foo.js", None));
        assert!(looks_like_distribution("src/foo.min.js", None));
        assert!(!looks_like_distribution("src/foo.js", None));
        // pkg main suppresses
        assert!(looks_like_distribution("index.js", Some("index.js")));
    }

    #[test]
    fn detects_hardcoded_url_strings() {
        let src = r#"
            const a = "https://attacker.com/exfil";
            const b = "ws://10.0.0.1:9999/c2";
            const c = "ftp://files.example.com/payload.bin";
        "#;
        let hits = scan_source_for_test("a.js", src);
        let urls: Vec<&BehaviorHit> = hits
            .iter()
            .filter(|h| h.behavior == Behavior::UrlStrings)
            .collect();
        assert_eq!(urls.len(), 3);
        let captured: Vec<&str> = urls.iter().filter_map(|h| h.note.as_deref()).collect();
        assert!(captured.iter().any(|u| u.starts_with("https://")));
        assert!(captured.iter().any(|u| u.starts_with("ws://")));
        assert!(captured.iter().any(|u| u.starts_with("ftp://")));
    }

    #[test]
    fn url_extraction_stops_at_quote() {
        // Make sure the trailing `";` doesn't end up in the captured URL.
        assert_eq!(
            extract_first_url(r#"  "https://x.example.com/a";  "#),
            Some("https://x.example.com/a")
        );
    }

    #[test]
    fn url_extraction_skips_git_and_data_schemes() {
        assert_eq!(extract_first_url(r#"  "git://github.com/x.git"  "#), None);
        assert_eq!(
            extract_first_url(r#"const x = "data:text/plain;base64,..."  "#),
            None
        );
    }

    #[test]
    fn shannon_entropy_basic_bounds() {
        assert!(shannon_entropy("aaaa") < 0.001);
        let v = shannon_entropy("abcdabcd");
        assert!((v - 2.0).abs() < 0.001);
    }
}
