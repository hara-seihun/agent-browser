//! Metadata-only progress for a protected observation's original deadline.
//! The connection and daemon retain the handle outside cancellable work. Nested
//! observers share one scope; the timeout snapshots active phases before drop.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    AttachmentHarvest,
    FrameSetup,
    InitialFrameTree,
    InitialDocument,
    Controls,
    ControlResolve,
    ControlValues,
    ControlRelease,
    AxTree,
    CursorProjection,
    SelectorProjection,
    FinalValidation,
    ObjectCleanup,
    RecoveryTargets,
    RecoveryAttach,
    DrainEvents,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeadlineDiagnostic {
    budget_ms: u128,
    elapsed_ms: u128,
    attempts: usize,
    phases: Vec<PhaseDiagnostic>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PhaseDiagnostic {
    phase: Phase,
    started: usize,
    completed: usize,
    cancelled: usize,
    in_flight: usize,
    active_max_ms: u128,
    total_ms: u128,
    max_ms: u128,
}

impl DeadlineDiagnostic {
    pub(crate) fn into_message(self) -> String {
        format!(
            "{}: frame observation deadline elapsed: {}",
            super::sensitive::UNSUPPORTED,
            serde_json::to_string(&self).expect("numeric observation diagnostic serializes")
        )
    }
}

#[derive(Default)]
struct Counts {
    started: usize,
    completed: usize,
    cancelled: usize,
    total_ms: u128,
    max_ms: u128,
    active: BTreeMap<usize, Instant>,
}

struct Running {
    scopes: usize,
    start: Instant,
    budget_ms: u128,
    attempts: usize,
    phases: BTreeMap<Phase, Counts>,
}

#[derive(Default)]
enum State {
    #[default]
    Unset,
    Running(Running),
}

#[derive(Clone, Default)]
pub(crate) struct ObservationProgress(Arc<Mutex<State>>);

struct Scope {
    progress: ObservationProgress,
}

impl Drop for Scope {
    fn drop(&mut self) {
        let mut state = self.progress.0.lock().expect("observation progress lock");
        let State::Running(running) = &mut *state else {
            panic!("observation scope unset")
        };
        running.scopes -= 1;
        if running.scopes == 0 {
            *state = State::Unset;
        }
    }
}

struct PhaseGuard {
    progress: ObservationProgress,
    phase: Phase,
    id: Option<usize>,
    completed: bool,
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        let Some(id) = self.id else { return };
        let mut state = self.progress.0.lock().expect("observation progress lock");
        let State::Running(running) = &mut *state else {
            panic!("active observation phase unset")
        };
        let counts = running
            .phases
            .get_mut(&self.phase)
            .expect("registered phase");
        let start = counts
            .active
            .remove(&id)
            .expect("registered phase invocation");
        let elapsed = start.elapsed().as_millis();
        counts.total_ms += elapsed;
        counts.max_ms = counts.max_ms.max(elapsed);
        if self.completed {
            counts.completed += 1;
        } else {
            counts.cancelled += 1;
        }
    }
}

impl ObservationProgress {
    fn scope(&self, deadline: Instant) -> Scope {
        let mut state = self.0.lock().expect("observation progress lock");
        match &mut *state {
            State::Unset => {
                let start = Instant::now();
                *state = State::Running(Running {
                    scopes: 1,
                    start,
                    budget_ms: deadline
                        .saturating_duration_since(start)
                        .as_micros()
                        .div_ceil(1000),
                    attempts: 0,
                    phases: BTreeMap::new(),
                });
            }
            State::Running(running) => running.scopes += 1,
        }
        Scope {
            progress: self.clone(),
        }
    }

    pub(crate) fn attempt(&self) {
        if let State::Running(running) = &mut *self.0.lock().expect("observation progress lock") {
            running.attempts += 1;
        }
    }

    pub(crate) async fn track<T>(&self, phase: Phase, operation: impl Future<Output = T>) -> T {
        let id = match &mut *self.0.lock().expect("observation progress lock") {
            State::Unset => None, // Setup outside protected observation is untracked.
            State::Running(running) => {
                let counts = running.phases.entry(phase).or_default();
                counts.started += 1;
                counts.active.insert(counts.started, Instant::now());
                Some(counts.started)
            }
        };
        let mut guard = PhaseGuard {
            progress: self.clone(),
            phase,
            id,
            completed: false,
        };
        let output = operation.await;
        guard.completed = true;
        output
    }

    fn diagnostic(&self) -> DeadlineDiagnostic {
        let state = self.0.lock().expect("observation progress lock");
        let State::Running(running) = &*state else {
            panic!("deadline without observation scope")
        };
        DeadlineDiagnostic {
            budget_ms: running.budget_ms,
            elapsed_ms: running.start.elapsed().as_millis(),
            attempts: running.attempts,
            phases: running
                .phases
                .iter()
                .map(|(&phase, counts)| PhaseDiagnostic {
                    phase,
                    started: counts.started,
                    completed: counts.completed,
                    cancelled: counts.cancelled,
                    in_flight: counts.active.len(),
                    active_max_ms: counts
                        .active
                        .values()
                        .map(|start| start.elapsed().as_millis())
                        .max()
                        .unwrap_or(0),
                    total_ms: counts.total_ms,
                    max_ms: counts.max_ms,
                })
                .collect(),
        }
    }

    pub(crate) async fn before<T>(
        &self,
        deadline: Instant,
        operation: impl Future<Output = T>,
    ) -> Result<T, DeadlineDiagnostic> {
        let _scope = self.scope(deadline);
        tokio::pin!(operation);
        tokio::select! {
            biased;
            // An expired owning deadline wins over a nested observer's result.
            // Otherwise a nested string error can erase the outer typed diagnostic
            // when both timers become ready in the same scheduler tick.
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => Err(self.diagnostic()),
            output = &mut operation => Ok(output),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_deadline_wins_over_ready_nested_result() {
        let progress = ObservationProgress::default();
        let result = progress
            .before(Instant::now(), async {
                Err::<(), _>("nested string error")
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cancelled_phase_retires_its_active_count_without_becoming_completed() {
        let progress = ObservationProgress::default();
        let diagnostic = progress
            .before(
                Instant::now() + std::time::Duration::from_millis(30),
                async {
                    let cancelled = tokio::time::timeout(
                        std::time::Duration::from_millis(5),
                        progress.track(Phase::Controls, std::future::pending::<()>()),
                    )
                    .await;
                    assert!(cancelled.is_err());
                    std::future::pending::<()>().await;
                },
            )
            .await
            .unwrap_err();
        assert_eq!(diagnostic.phases.len(), 1);
        let phase = &diagnostic.phases[0];
        assert_eq!(
            (
                phase.started,
                phase.completed,
                phase.cancelled,
                phase.in_flight
            ),
            (1, 0, 1, 0)
        );
        assert!(matches!(*progress.0.lock().unwrap(), State::Unset));
    }

    #[tokio::test]
    async fn nested_deadlines_keep_original_budget_and_concurrent_phases() {
        let progress = ObservationProgress::default();
        let deadline = Instant::now() + std::time::Duration::from_millis(30);
        let diagnostic = progress
            .before(deadline, async {
                progress.attempt();
                progress
                    .before(Instant::now() + std::time::Duration::from_secs(2), async {
                        tokio::join!(
                            progress.track(Phase::Controls, std::future::pending::<()>()),
                            progress.track(Phase::AxTree, std::future::pending::<()>()),
                        );
                    })
                    .await
            })
            .await
            .unwrap_err();
        assert_eq!(diagnostic.budget_ms, 30);
        assert_eq!(diagnostic.attempts, 1);
        assert_eq!(diagnostic.phases.len(), 2);
        assert!(diagnostic
            .phases
            .iter()
            .all(|p| p.started == 1 && p.in_flight == 1 && p.completed == 0));
        assert!(matches!(*progress.0.lock().unwrap(), State::Unset));
        let next = progress
            .before(
                Instant::now() + std::time::Duration::from_millis(10),
                std::future::pending::<()>(),
            )
            .await
            .unwrap_err();
        assert!(next.phases.is_empty());
        assert_eq!(next.attempts, 0);
    }
}
