//! [`VaultTree`] — pure in-memory tree over a set of [`VaultPath`]s,
//! with pass-style text rendering for `shuki ls` and substring filtering.

use std::collections::BTreeMap;

use super::path::VaultPath;

#[derive(Debug, Default, Clone)]
struct Node {
    children: BTreeMap<String, Node>,
    /// True if some path terminates exactly here (an entry, not just a directory).
    is_entry: bool,
}

/// Immutable tree built from entry paths. Holds no secrets.
#[derive(Debug, Default, Clone)]
pub struct VaultTree {
    paths: Vec<VaultPath>,
    root: Node,
}

impl VaultTree {
    pub fn build(paths: &[VaultPath]) -> Self {
        let mut sorted: Vec<VaultPath> = paths.to_vec();
        sorted.sort();
        sorted.dedup();
        let mut root = Node::default();
        for p in &sorted {
            let mut node = &mut root;
            for seg in p.segments() {
                node = node.children.entry(seg.to_owned()).or_default();
            }
            node.is_entry = true;
        }
        Self {
            paths: sorted,
            root,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// All entry paths, sorted.
    pub fn paths(&self) -> &[VaultPath] {
        &self.paths
    }

    /// Pass-style unicode tree. `root == None` renders from the top;
    /// otherwise renders the subtree at `root` (empty string if absent).
    pub fn render_text(&self, root: Option<&VaultPath>) -> String {
        let (label, node) = match root {
            None => ("shuki".to_owned(), Some(&self.root)),
            Some(p) => (p.as_str().to_owned(), self.find(p)),
        };
        let Some(node) = node else {
            return String::new();
        };
        let mut out = String::new();
        out.push_str(&label);
        out.push('\n');
        render_children(node, "", &mut out);
        out
    }

    /// Keep only paths whose full string contains `substr` (case-insensitive).
    pub fn filter(&self, substr: &str) -> VaultTree {
        let needle = substr.to_lowercase();
        let kept: Vec<VaultPath> = self
            .paths
            .iter()
            .filter(|p| p.as_str().to_lowercase().contains(&needle))
            .cloned()
            .collect();
        Self::build(&kept)
    }

    fn find(&self, path: &VaultPath) -> Option<&Node> {
        let mut node = &self.root;
        for seg in path.segments() {
            node = node.children.get(seg)?;
        }
        Some(node)
    }
}

fn render_children(node: &Node, prefix: &str, out: &mut String) {
    let last_idx = node.children.len().saturating_sub(1);
    for (i, (name, child)) in node.children.iter().enumerate() {
        let (branch, cont) = if i == last_idx {
            ("└── ", "    ")
        } else {
            ("├── ", "│   ")
        };
        out.push_str(prefix);
        out.push_str(branch);
        out.push_str(name);
        out.push('\n');
        render_children(child, &format!("{prefix}{cont}"), out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(ps: &[&str]) -> Vec<VaultPath> {
        ps.iter().map(|p| VaultPath::parse(p).unwrap()).collect()
    }

    #[test]
    fn build_sorts_and_dedups() {
        let t = VaultTree::build(&paths(&["b", "a/x", "a/x", "a/y"]));
        let got: Vec<&str> = t.paths().iter().map(|p| p.as_str()).collect();
        assert_eq!(got, ["a/x", "a/y", "b"]);
    }

    #[test]
    fn render_full_tree() {
        let t = VaultTree::build(&paths(&[
            "web/github.com/alice",
            "web/example.com",
            "bank/main",
        ]));
        let expected = "\
shuki
├── bank
│   └── main
└── web
    ├── example.com
    └── github.com
        └── alice
";
        assert_eq!(t.render_text(None), expected);
    }

    #[test]
    fn render_subtree_and_missing() {
        let t = VaultTree::build(&paths(&["web/github.com/alice", "bank/main"]));
        let sub = t.render_text(Some(&VaultPath::parse("web").unwrap()));
        assert!(sub.starts_with("web\n"));
        assert!(sub.contains("github.com"));
        assert!(!sub.contains("bank"));
        assert_eq!(t.render_text(Some(&VaultPath::parse("nope").unwrap())), "");
    }

    #[test]
    fn filter_case_insensitive() {
        let t = VaultTree::build(&paths(&["web/GitHub.com/alice", "bank/main"]));
        let f = t.filter("github");
        assert_eq!(f.paths().len(), 1);
        assert!(t.filter("zzz").is_empty());
    }
}
