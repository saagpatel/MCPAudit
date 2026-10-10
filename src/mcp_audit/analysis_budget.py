"""Cooperative wall-clock deadlines for synchronous Python analysis stages."""

from __future__ import annotations

import contextlib
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from types import FrameType
from typing import Protocol


class AnalysisTimeout(TimeoutError):
    """The server's wall-clock budget expired before analysis completed."""


class _Trace(Protocol):
    def __call__(self, frame: FrameType, event: str, arg: object, /) -> _Trace | None: ...


@contextmanager
def analysis_budget(deadline: float) -> Iterator[None]:
    """Interrupt Python loops without abandoning work in a background thread.

    Only synchronous stages enter this scope: no task can suspend with a
    thread-wide trace installed. Native calls are checked on return, not preempted.
    """
    previous = sys.gettrace()
    caller = sys._getframe(2)  # contextlib.__enter__ -> synchronous analysis stage
    previous_local = caller.f_trace

    def check() -> None:
        if time.monotonic() >= deadline:
            raise AnalysisTimeout("Per-server wall-clock budget exhausted; analysis is incomplete.")

    def trace(frame: FrameType, event: str, arg: object) -> _Trace | None:
        # Let the context manager unwind and restore tracing even at expiry.
        if frame.f_code.co_filename in {__file__, contextlib.__file__}:
            return None
        check()
        return trace

    check()
    try:
        sys.settrace(trace)
        caller.f_trace = trace
        yield
        check()
    finally:
        caller.f_trace = previous_local
        sys.settrace(previous)
