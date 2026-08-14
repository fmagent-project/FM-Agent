use proc_macro2::LineColumn;
use quote::ToTokens;
use std::{env, fs, path::Path, process};
use syn::{spanned::Spanned, visit::Visit, Block, ImplItemFn, ItemFn, TraitItemFn};

struct BodyFinder<'a> {
    name: &'a str,
    wanted: usize,
    seen: usize,
    range: Option<(LineColumn, LineColumn)>,
    normalized_body: Option<String>,
}

impl BodyFinder<'_> {
    fn record(&mut self, name: &syn::Ident, block: &Block) {
        if name == self.name {
            if self.seen == self.wanted {
                let span = block.span();
                self.range = Some((span.start(), span.end()));
                self.normalized_body = Some(block.to_token_stream().to_string());
            }
            self.seen += 1;
        }
    }
}

impl<'ast> Visit<'ast> for BodyFinder<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.record(&node.sig.ident, &node.block);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.record(&node.sig.ident, &node.block);
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        if let Some(block) = &node.default {
            self.record(&node.sig.ident, block);
        }
        syn::visit::visit_trait_item_fn(self, node);
    }
}

fn byte_offset(source: &str, location: LineColumn) -> Result<usize, String> {
    if location.line == 0 {
        return Err("Rust parser returned an invalid zero line".to_string());
    }
    let line_start = if location.line == 1 {
        0
    } else {
        source
            .match_indices('\n')
            .nth(location.line - 2)
            .map(|(index, _)| index + 1)
            .ok_or_else(|| "Rust parser span line is outside the source".to_string())?
    };
    let offset = line_start + location.column;
    if offset > source.len() || !source.is_char_boundary(offset) {
        return Err("Rust parser span column is outside the source".to_string());
    }
    Ok(offset)
}

fn target_body_snapshot(
    source: &str,
    name: &str,
    occurrence: usize,
) -> Result<(String, String), String> {
    let file = syn::parse_file(source).map_err(|error| format!("Rust parse failed: {error}"))?;
    let mut finder = BodyFinder {
        name,
        wanted: occurrence,
        seen: 0,
        range: None,
        normalized_body: None,
    };
    finder.visit_file(&file);
    let (start, end) = finder
        .range
        .ok_or_else(|| format!("target function {name} occurrence {occurrence} was not found"))?;
    let start = byte_offset(source, start)?;
    let end = byte_offset(source, end)?;
    if start > end {
        return Err("Rust parser returned a reversed target body span".to_string());
    }
    let outside = format!("{}<FM_TARGET_BODY>{}", &source[..start], &source[end..]);
    let normalized_body = finder
        .normalized_body
        .ok_or_else(|| "target function body could not be normalized".to_string())?;
    Ok((outside, normalized_body))
}

// PIN: l1-patches-are-narrow-and-behaviorally-closed
fn check(before: &str, after: &str, name: &str, occurrence: usize) -> Result<(), String> {
    let (before_outside, before_body) = target_body_snapshot(before, name, occurrence)?;
    let (after_outside, after_body) = target_body_snapshot(after, name, occurrence)?;
    if before_outside != after_outside {
        return Err("patch changes code outside the target function body".to_string());
    }
    if before_body == after_body {
        return Err(
            "patch does not change the parsed target function body; comments and whitespace do not count"
                .to_string(),
        );
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return Err("usage: l1_scope <before.rs> <after.rs> <function> <occurrence>".to_string());
    }
    let occurrence = args[4]
        .parse::<usize>()
        .map_err(|_| "occurrence must be a non-negative integer".to_string())?;
    check(
        &read(Path::new(&args[1]))?,
        &read(Path::new(&args[2]))?,
        &args[3],
        occurrence,
    )
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::check;

    const BEFORE: &str = r#"
        use std::fmt;
        struct Demo;
        impl Demo {
            #[inline]
            fn target(&self) -> i32 { 1 }
            fn neighbor(&self) -> i32 { 2 }
        }
    "#;

    #[test]
    fn accepts_only_target_body_change() {
        assert!(check(BEFORE, &BEFORE.replace("{ 1 }", "{ 3 }"), "target", 0).is_ok());
    }

    #[test]
    fn rejects_changes_outside_target_body() {
        for after in [
            BEFORE.replace("fn target(&self)", "fn target(&mut self)"),
            BEFORE.replace("#[inline]", "#[cold]"),
            BEFORE.replace("use std::fmt;", "use std::io;"),
            BEFORE.replace("{ 2 }", "{ 4 }"),
            BEFORE.replace("use std::fmt;", "// changed outside\nuse std::fmt;"),
        ] {
            assert!(check(BEFORE, &after, "target", 0).is_err());
        }
    }

    #[test]
    fn accepts_comment_changes_inside_target_body() {
        let after = BEFORE.replace("{ 1 }", "{ /* explanation */ 3 }");
        assert!(check(BEFORE, &after, "target", 0).is_ok());
    }

    #[test]
    fn rejects_comment_or_whitespace_only_target_changes() {
        for after in [
            BEFORE.replace("{ 1 }", "{ /* no repair */ 1 }"),
            BEFORE.replace("{ 1 }", "{\n                1\n            }"),
        ] {
            let error = check(BEFORE, &after, "target", 0).unwrap_err();
            assert!(error.contains("does not change the parsed target function body"));
        }
    }

    #[test]
    fn honors_occurrence() {
        let before = "fn same(){one();} mod nested { fn same(){two();} }";
        let second = before.replace("two();", "three();");
        assert!(check(before, &second, "same", 1).is_ok());
        assert!(check(before, &second, "same", 0).is_err());
    }
}
