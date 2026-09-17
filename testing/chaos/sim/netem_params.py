"""Shared, dependency-free arguments for one direction of a netem link."""

from dataclasses import dataclass, replace
import math


@dataclass
class NetemParams:
    """Concrete netem parameters for one link direction."""

    delay_ms: int = 0
    jitter_ms: int = 0
    loss_pct: float = 0.0
    duplicate_pct: float = 0.0
    reorder_pct: float = 0.0
    corrupt_pct: float = 0.0
    gap: int = 0

    def to_tc_argv(self) -> list[str]:
        for value in (self.delay_ms, self.jitter_ms, self.gap):
            if type(value) is not int or value < 0:
                raise ValueError("netem delays and gap must be nonnegative integers")
        for value in (self.loss_pct, self.duplicate_pct, self.reorder_pct, self.corrupt_pct):
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100:
                raise ValueError("netem percentages must be finite numbers between zero and 100")
        if (self.jitter_ms or self.reorder_pct) and not self.delay_ms:
            raise ValueError("netem jitter and reordering require a delay")
        if self.gap and not self.reorder_pct:
            raise ValueError("netem gap requires reordering")
        parts = []
        if self.delay_ms:
            parts += ["delay", f"{self.delay_ms}ms"]
            if self.jitter_ms:
                parts.append(f"{self.jitter_ms}ms")
        for name, value in (("loss", self.loss_pct), ("duplicate", self.duplicate_pct),
                            ("reorder", self.reorder_pct)):
            if value:
                parts += [name, f"{value:.1f}%"]
        if self.gap:
            parts += ["gap", str(self.gap)]
        if self.corrupt_pct:
            parts += ["corrupt", f"{self.corrupt_pct:.1f}%"]
        return parts or ["delay", "0ms"]

    def to_tc_args(self) -> str:
        """Retain the existing simulator's shell-argument interface."""
        # A sampled delay can round to zero. The legacy simulator omitted
        # dependent flags in that case; explicit scoped requests stay strict.
        params = replace(self, jitter_ms=0, reorder_pct=0, gap=0) if self.delay_ms == 0 else self
        return " ".join(params.to_tc_argv())
