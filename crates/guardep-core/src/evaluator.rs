//! Registry that runs all enabled evaluators in parallel and merges
//! their findings into a single ordered list.

use crate::ecosystem::PackageRef;
use crate::finding::{Evaluator, Finding};
use crate::policy::Policy;
use anyhow::Result;
use futures::future::join_all;
use std::sync::Arc;

#[derive(Default)]
pub struct EvaluatorRegistry {
    evaluators: Vec<Arc<dyn Evaluator>>,
}

impl EvaluatorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, evaluator: Arc<dyn Evaluator>) {
        self.evaluators.push(evaluator);
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.evaluators.iter().map(|e| e.name()).collect()
    }

    pub async fn run(&self, packages: &[PackageRef], policy: &Policy) -> Result<Vec<Finding>> {
        let active: Vec<_> = self
            .evaluators
            .iter()
            .filter(|e| e.enabled(policy))
            .collect();

        let futures = active.iter().map(|e| {
            let pkgs = packages;
            let pol = policy;
            async move {
                let name = e.name();
                match e.evaluate(pkgs, pol).await {
                    Ok(f) => {
                        tracing::info!(evaluator = name, count = f.len(), "evaluator complete");
                        f
                    }
                    Err(err) => {
                        tracing::warn!(evaluator = name, %err, "evaluator failed — skipping");
                        Vec::new()
                    }
                }
            }
        });

        let mut all: Vec<Finding> = join_all(futures).await.into_iter().flatten().collect();

        // Stable order: by package name, then version, then kind, then id.
        all.sort_by(|a, b| {
            (
                &a.package.name,
                &a.package.version,
                a.kind.as_str(),
                &a.id,
            )
                .cmp(&(
                    &b.package.name,
                    &b.package.version,
                    b.kind.as_str(),
                    &b.id,
                ))
        });
        Ok(all)
    }
}

/// Convenience: run a registry and return findings.
pub async fn evaluate_all(
    registry: &EvaluatorRegistry,
    packages: &[PackageRef],
    policy: &Policy,
) -> Result<Vec<Finding>> {
    registry.run(packages, policy).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::Ecosystem;
    use crate::finding::{FindingKind, FindingSeverity};
    use async_trait::async_trait;

    struct StubEval(&'static str, FindingKind);
    #[async_trait]
    impl Evaluator for StubEval {
        fn name(&self) -> &'static str {
            self.0
        }
        fn enabled(&self, _: &Policy) -> bool {
            true
        }
        async fn evaluate(&self, packages: &[PackageRef], _: &Policy) -> Result<Vec<Finding>> {
            Ok(packages
                .iter()
                .map(|p| Finding {
                    package: p.clone(),
                    kind: self.1,
                    id: format!("{}:{}", self.0, p.name),
                    aliases: vec![],
                    summary: String::new(),
                    severity: FindingSeverity::High,
                    fixed_versions: vec![],
                    references: vec![],
                    details: serde_json::Value::Null,
                })
                .collect())
        }
    }

    #[tokio::test]
    async fn registry_merges_evaluator_results() {
        let mut reg = EvaluatorRegistry::new();
        reg.register(Arc::new(StubEval("a", FindingKind::Vulnerability)));
        reg.register(Arc::new(StubEval("b", FindingKind::RiskScore)));
        let pkgs = vec![PackageRef::new(Ecosystem::Npm, "x", "1.0.0")];
        let policy = Policy::default();
        let findings = reg.run(&pkgs, &policy).await.unwrap();
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.kind == FindingKind::Vulnerability));
        assert!(findings.iter().any(|f| f.kind == FindingKind::RiskScore));
    }
}
