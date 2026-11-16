"""Pytest Configuration and Platform-Specific Environment Fixtures.

Module: backend.tests.conftest
Owner: M1 / M7
"""

import sys

# Windows Sandbox loopback socket fallback for ProactorEventLoop inter-thread signaling
if sys.platform == "win32":
    import os
    import signal
    import _overlapped
    import asyncio.proactor_events

    # Safe no-op wakeup FD handler to prevent STATUS_INVALID_HANDLE on pipe descriptors in sandbox
    signal.set_wakeup_fd = lambda fd, *args, **kwargs: -1

    class _PipeSocket:
        """Wrapper around os.pipe for Windows environments where loopback socket connects are blocked."""
        def __init__(self, fd: int) -> None:
            self.fd = fd

        def fileno(self) -> int:
            return self.fd

        def setblocking(self, b: bool) -> None:
            pass

        def close(self) -> None:
            try:
                os.close(self.fd)
            except OSError:
                pass

    def _safe_make_self_pipe(self):
        r, w = os.pipe()
        self._ssock = _PipeSocket(r)
        self._csock = _PipeSocket(w)
        self._internal_fds += 1
        self._wake_ov = _overlapped.Overlapped()

    def _safe_close_self_pipe(self):
        if getattr(self, "_ssock", None):
            self._ssock.close()
            self._ssock = None
        if getattr(self, "_csock", None):
            self._csock.close()
            self._csock = None
        self._wake_ov = None
        self._internal_fds -= 1

    def _safe_write_to_self(self):
        if hasattr(self, "_proactor") and hasattr(self._proactor, "_iocp") and getattr(self, "_wake_ov", None) is not None:
            try:
                _overlapped.PostQueuedCompletionStatus(self._proactor._iocp, 0, 0, self._wake_ov.address)
            except OSError:
                pass

    asyncio.proactor_events.BaseProactorEventLoop._make_self_pipe = _safe_make_self_pipe
    asyncio.proactor_events.BaseProactorEventLoop._close_self_pipe = _safe_close_self_pipe
    asyncio.proactor_events.BaseProactorEventLoop._loop_self_reading = lambda self, f=None: None
    asyncio.proactor_events.BaseProactorEventLoop._write_to_self = _safe_write_to_self
