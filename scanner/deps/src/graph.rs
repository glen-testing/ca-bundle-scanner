use crate::ResolvedDep;
use petgraph::graph::{Graph, NodeIndex};
use std::collections::{HashMap, VecDeque};

/// Dependency graph keyed by (name, version), so multiple versions of a package stay distinct.
pub struct DepGraph {
    pub graph: Graph<ResolvedDep, ()>,
    pub root: NodeIndex,
    by_key: HashMap<(String, String), NodeIndex>,
    by_name: HashMap<String, Vec<NodeIndex>>,
}

impl DepGraph {
    pub fn new(root_dep: ResolvedDep) -> Self {
        let mut g = Self {
            graph: Graph::new(),
            root: NodeIndex::new(0),
            by_key: HashMap::new(),
            by_name: HashMap::new(),
        };
        g.root = g.add_dep(root_dep);
        g
    }

    pub fn add_dep(&mut self, dep: ResolvedDep) -> NodeIndex {
        let key = (dep.name.clone(), dep.version.clone());
        if let Some(&idx) = self.by_key.get(&key) {
            if self.graph[idx].location.is_none() && dep.location.is_some() {
                self.graph[idx].location = dep.location;
            }
            return idx;
        }
        let name = dep.name.clone();
        let idx = self.graph.add_node(dep);
        self.by_key.insert(key, idx);
        self.by_name.entry(name).or_default().push(idx);
        idx
    }

    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex) {
        if from != to && !self.graph.contains_edge(from, to) {
            self.graph.add_edge(from, to, ());
        }
    }

    pub fn find_all(&self, name: &str) -> &[NodeIndex] {
        self.by_name.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn find_version(&self, name: &str, version: &str) -> Option<NodeIndex> {
        self.by_key
            .get(&(name.to_string(), version.to_string()))
            .copied()
    }

    /// Single version of `name`, if exactly one exists.
    pub fn find_unique(&self, name: &str) -> Option<NodeIndex> {
        match self.find_all(name) {
            [one] => Some(*one),
            _ => None,
        }
    }

    pub fn has_dep(&self, name: &str) -> bool {
        !self.find_all(name).is_empty()
    }

    /// Shortest chain from root to `target`, or None when no path exists.
    pub fn path_to(&self, target: NodeIndex) -> Option<Vec<String>> {
        let mut parent: HashMap<NodeIndex, NodeIndex> = HashMap::new();
        let mut queue = VecDeque::from([self.root]);
        let mut seen = std::collections::HashSet::from([self.root]);
        while let Some(n) = queue.pop_front() {
            if n == target {
                let mut chain = vec![n];
                let mut cur = n;
                while let Some(&p) = parent.get(&cur) {
                    chain.push(p);
                    cur = p;
                }
                chain.reverse();
                return Some(chain.iter().map(|&i| self.label(i)).collect());
            }
            for next in self.graph.neighbors(n) {
                if seen.insert(next) {
                    parent.insert(next, n);
                    queue.push_back(next);
                }
            }
        }
        None
    }

    pub fn label(&self, idx: NodeIndex) -> String {
        let d = &self.graph[idx];
        if d.version.is_empty() {
            d.name.clone()
        } else {
            format!("{} {}", d.name, d.version)
        }
    }

    pub fn dep_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Links root to every node with no incoming edges (used when a lockfile names no roots).
    pub fn link_orphans_to_root(&mut self) {
        let orphans: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| n != self.root)
            .filter(|&n| {
                self.graph
                    .neighbors_directed(n, petgraph::Direction::Incoming)
                    .next()
                    .is_none()
            })
            .collect();
        for n in orphans {
            self.add_edge(self.root, n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ecosystem;

    fn dep(name: &str, version: &str) -> ResolvedDep {
        ResolvedDep::new(name, version, Ecosystem::Rust)
    }

    #[test]
    fn tp_path_through_intermediates() {
        let mut g = DepGraph::new(dep("app", "0.1.0"));
        let rq = g.add_dep(dep("reqwest", "0.12.0"));
        let wp = g.add_dep(dep("webpki-roots", "0.26.0"));
        g.add_edge(g.root, rq);
        g.add_edge(rq, wp);
        assert_eq!(
            g.path_to(wp).unwrap(),
            vec!["app 0.1.0", "reqwest 0.12.0", "webpki-roots 0.26.0"]
        );
    }

    #[test]
    fn fp_no_path_when_disconnected() {
        let mut g = DepGraph::new(dep("app", "0.1.0"));
        let wp = g.add_dep(dep("webpki-roots", "0.26.0"));
        assert!(g.path_to(wp).is_none());
    }

    #[test]
    fn tp_two_versions_stay_distinct() {
        let mut g = DepGraph::new(dep("app", "0.1.0"));
        let a = g.add_dep(dep("webpki-roots", "0.25.4"));
        let b = g.add_dep(dep("webpki-roots", "0.26.3"));
        assert_ne!(a, b);
        assert_eq!(g.find_all("webpki-roots").len(), 2);
        assert!(g.find_unique("webpki-roots").is_none());
    }

    #[test]
    fn fp_same_version_not_duplicated() {
        let mut g = DepGraph::new(dep("app", "0.1.0"));
        let a = g.add_dep(dep("foo", "1.0.0"));
        let b = g.add_dep(dep("foo", "1.0.0"));
        assert_eq!(a, b);
        assert_eq!(g.dep_count(), 2);
    }

    #[test]
    fn orphans_linked_but_not_children() {
        let mut g = DepGraph::new(dep("(root)", ""));
        let top = g.add_dep(dep("requests", "2.0"));
        let child = g.add_dep(dep("certifi", "2024.8.30"));
        g.add_edge(top, child);
        g.link_orphans_to_root();
        assert!(g.graph.contains_edge(g.root, top));
        assert!(!g.graph.contains_edge(g.root, child));
    }
}
