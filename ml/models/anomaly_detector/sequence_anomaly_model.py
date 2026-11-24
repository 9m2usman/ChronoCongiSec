"""Unsupervised Behavioral & Execution-Sequence Anomaly Detector.

Models per-department/role normal tool-operation transition probabilities
(first-order Markov chain with Laplace smoothing), action frequency priors,
and numeric parameter distributions (mean/std z-score).

Runtime sliding windows are strictly partitioned by ``(tenant_id, branch_id, agent_id)``
so no behavioral state ever leaks across tenants, branches, or agents.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Sequence, Tuple

from ml.features.extractor import BehavioralEvent


def _sigmoid(z: float) -> float:
    if z >= 35.0:
        return 1.0 - 1e-15
    if z <= -35.0:
        return 1e-15
    return 1.0 / (1.0 + math.exp(-z))


@dataclass(frozen=True)
class BehavioralAnomalyPrediction:
    """Advisory behavioral anomaly assessment."""

    anomaly_score: float
    is_anomalous: bool
    threshold: float
    sequence_surprise: float
    frequency_surprise: float
    parameter_zscore: float
    burst_score: float
    reason_factors: Tuple[str, ...]
    model_version: str


@dataclass
class _DepartmentBaseline:
    transition_counts: Dict[str, Dict[str, int]] = field(default_factory=dict)
    action_counts: Dict[str, int] = field(default_factory=dict)
    total_actions: int = 0
    amount_count: int = 0
    amount_mean: float = 0.0
    amount_m2: float = 0.0

    @property
    def amount_std(self) -> float:
        if self.amount_count < 2:
            return 1.0
        return max(1.0, math.sqrt(self.amount_m2 / (self.amount_count - 1)))

    def observe(self, prev_action: Optional[str], curr_action: str, amount: Optional[float]) -> None:
        self.action_counts[curr_action] = self.action_counts.get(curr_action, 0) + 1
        self.total_actions += 1
        if prev_action is not None:
            row = self.transition_counts.setdefault(prev_action, {})
            row[curr_action] = row.get(curr_action, 0) + 1
        if amount is not None and math.isfinite(amount):
            self.amount_count += 1
            delta = amount - self.amount_mean
            self.amount_mean += delta / self.amount_count
            delta2 = amount - self.amount_mean
            self.amount_m2 += delta * delta2


@dataclass
class BehavioralSequenceAnomalyDetector:
    """Unsupervised Markov + statistical behavioral anomaly detector."""

    version: str = "behavior-markov-z/1.0.0"
    laplace_alpha: float = 0.5
    threshold: float = 0.62
    window_size: int = 20
    max_tracked_agents: int = 10_000
    baselines: Dict[str, _DepartmentBaseline] = field(default_factory=dict)
    # Runtime state strictly keyed by (tenant_id, branch_id, agent_id)
    _agent_history: Dict[Tuple[str, str, str], Deque[Tuple[str, float]]] = field(
        default_factory=dict, repr=False
    )

    def fit_sequences(self, sequences: Sequence[Sequence[BehavioralEvent]]) -> "BehavioralSequenceAnomalyDetector":
        """Fit unsupervised role-conditioned baselines from benign execution sequences."""
        self.baselines = {}
        for seq in sequences:
            prev_action: Optional[str] = None
            for ev in seq:
                dept = ev.department or "general"
                base = self.baselines.setdefault(dept, _DepartmentBaseline())
                base.observe(prev_action, ev.action_key, ev.amount)
                prev_action = ev.action_key
        return self

    def _get_baseline(self, department: str) -> Optional[_DepartmentBaseline]:
        dept = (department or "general").lower()
        if dept in self.baselines:
            return self.baselines[dept]
        # Partial match (e.g., "customer_support" vs "customer support")
        for k, v in self.baselines.items():
            if k in dept or dept in k:
                return v
        return self.baselines.get("general")

    def score_event(
        self,
        event: BehavioralEvent,
        *,
        record_in_window: bool = True,
    ) -> BehavioralAnomalyPrediction:
        """Score a single event in the context of its (tenant, branch, agent) window."""
        scope_key = (event.tenant_id, event.branch_id, event.agent_id)
        history = self._agent_history.get(scope_key)
        if history is None:
            if len(self._agent_history) >= self.max_tracked_agents:
                oldest_key = next(iter(self._agent_history))
                self._agent_history.pop(oldest_key, None)
            history = deque(maxlen=self.window_size)
            self._agent_history[scope_key] = history

        prev_action = history[-1][0] if history else None
        base = self._get_baseline(event.department)

        seq_surprise = 0.0
        freq_surprise = 0.0
        param_z = 0.0
        burst_score = 0.0
        reasons: List[str] = []

        if base is not None and base.total_actions > 0:
            vocab_size = max(2, len(base.action_counts) + 1)
            # 1. Action frequency surprise: -log P(a) normalized
            c_act = base.action_counts.get(event.action_key, 0)
            p_act = (c_act + self.laplace_alpha) / (base.total_actions + self.laplace_alpha * vocab_size)
            max_ent = math.log(base.total_actions + self.laplace_alpha * vocab_size)
            freq_surprise = min(1.0, max(0.0, (-math.log(p_act) - 0.5) / max(1.0, max_ent)))
            if c_act == 0:
                reasons.append(f"unseen_action_for_role:{event.action_key}")

            # 2. First-order Markov transition surprise: -log P(a_t | a_{t-1})
            if prev_action is not None:
                row = base.transition_counts.get(prev_action, {})
                row_total = sum(row.values())
                c_trans = row.get(event.action_key, 0)
                p_trans = (c_trans + self.laplace_alpha) / (row_total + self.laplace_alpha * vocab_size)
                t_ent = math.log(row_total + self.laplace_alpha * vocab_size)
                seq_surprise = min(1.0, max(0.0, (-math.log(p_trans) - 0.3) / max(1.0, t_ent)))
                if c_trans == 0 and c_act > 0:
                    reasons.append(f"unusual_transition:{prev_action}->{event.action_key}")

            # 3. Numeric parameter z-score (e.g. amount)
            if event.amount is not None and base.amount_count >= 3:
                raw_z = abs(event.amount - base.amount_mean) / base.amount_std
                param_z = min(1.0, max(0.0, (raw_z - 1.5) / 4.0))
                if raw_z >= 3.0:
                    reasons.append(f"parameter_amount_outlier:z={raw_z:.2f}")

        # 4. Short-window burstiness / repetition in isolated agent window
        if event.timestamp > 0.0 and history:
            recent_10s = sum(1 for _, ts in history if 0.0 <= (event.timestamp - ts) <= 10.0)
            if recent_10s >= 3:
                burst_score = min(1.0, recent_10s / 6.0)
                reasons.append(f"short_window_burst:{recent_10s}_in_10s")

        if record_in_window:
            history.append((event.action_key, event.timestamp))

        # Weighted combination mapped through calibrated sigmoid
        raw_combo = (
            0.35 * freq_surprise
            + 0.35 * seq_surprise
            + 0.20 * param_z
            + 0.10 * burst_score
        )
        # Center around 0.45 so normal transitions score ~0.15-0.30 and unseen/outlier >= 0.65
        anomaly_score = _sigmoid((raw_combo - 0.42) * 6.0)

        return BehavioralAnomalyPrediction(
            anomaly_score=anomaly_score,
            is_anomalous=anomaly_score >= self.threshold,
            threshold=self.threshold,
            sequence_surprise=round(seq_surprise, 4),
            frequency_surprise=round(freq_surprise, 4),
            parameter_zscore=round(param_z, 4),
            burst_score=round(burst_score, 4),
            reason_factors=tuple(reasons),
            model_version=self.version,
        )

    def clear_agent_window(self, tenant_id: str, branch_id: str, agent_id: str) -> None:
        self._agent_history.pop((tenant_id, branch_id, agent_id), None)

    def to_dict(self) -> Dict[str, object]:
        ser_baselines: Dict[str, object] = {}
        for dept, b in self.baselines.items():
            ser_baselines[dept] = {
                "transition_counts": b.transition_counts,
                "action_counts": b.action_counts,
                "total_actions": b.total_actions,
                "amount_count": b.amount_count,
                "amount_mean": b.amount_mean,
                "amount_m2": b.amount_m2,
            }
        return {
            "model_type": "BehavioralSequenceAnomalyDetector",
            "version": self.version,
            "laplace_alpha": self.laplace_alpha,
            "threshold": self.threshold,
            "window_size": self.window_size,
            "baselines": ser_baselines,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "BehavioralSequenceAnomalyDetector":
        baselines: Dict[str, _DepartmentBaseline] = {}
        raw_b = dict(data.get("baselines", {}))  # type: ignore[arg-type]
        for dept, bdata in raw_b.items():
            bd = dict(bdata)  # type: ignore[arg-type]
            baselines[str(dept)] = _DepartmentBaseline(
                transition_counts={
                    str(k): {str(k2): int(v2) for k2, v2 in dict(v).items()}
                    for k, v in dict(bd.get("transition_counts", {})).items()
                },
                action_counts={str(k): int(v) for k, v in dict(bd.get("action_counts", {})).items()},
                total_actions=int(bd.get("total_actions", 0)),
                amount_count=int(bd.get("amount_count", 0)),
                amount_mean=float(bd.get("amount_mean", 0.0)),
                amount_m2=float(bd.get("amount_m2", 0.0)),
            )
        return cls(
            version=str(data["version"]),
            laplace_alpha=float(data.get("laplace_alpha", 0.5)),  # type: ignore[arg-type]
            threshold=float(data.get("threshold", 0.62)),  # type: ignore[arg-type]
            window_size=int(data.get("window_size", 20)),  # type: ignore[arg-type]
            baselines=baselines,
        )
