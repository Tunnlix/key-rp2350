"""python-fido2 report transport for the C harness, without USB discovery.

This module only exchanges unprefixed 64-byte reports. CtapHidDevice generates
request headers/fragments, verifies INIT, and assembles replies. The C coordinator
owns authenticator-side protocol behavior. Calls on one connection are serial.
"""

from __future__ import annotations

from collections import deque
import math
from pathlib import Path
from queue import Empty, Queue
import subprocess
from threading import Thread
import tempfile
import json

from fido2.hid import ConnectionFailure, CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor

REPORT_SIZE = 64


class HarnessConnection(CtapHidConnection):
    """Bounded reads, exact report I/O, and explicit subprocess cleanup.

    stderr inherits the terminal so diagnostics cannot corrupt report bytes or
    fill an unread stderr pipe. Recent traffic is retained for test inspection.
    A read timeout closes the connection to avoid reusing out-of-order replies.
    """

    def __init__(self, executable: str | Path, timeout: float = 5.0, *, user_presence: bool = True):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        self.timeout = timeout
        self.sent_reports: deque[bytes] = deque(maxlen=256)
        self.received_reports: deque[bytes] = deque(maxlen=256)
        self._closed = False
        self._packets: Queue[bytes | Exception] = Queue()
        self._presence_directory = tempfile.TemporaryDirectory(prefix="ctaphid-presence-") if user_presence else None
        arguments = [str(Path(executable).resolve()), "--stdio"]
        if self._presence_directory:
            arguments += ["--presence-control", self._presence_directory.name]
        try:
            self.process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        except BaseException:
            if self._presence_directory:
                self._presence_directory.cleanup()
            raise
        self._reader = Thread(target=self._read_reports, name="ctaphid-reports", daemon=True)
        self._reader.start()

    def _read_reports(self) -> None:
        assert self.process.stdout is not None
        try:
            while True:
                report = bytearray()
                while len(report) < REPORT_SIZE:
                    chunk = self.process.stdout.read(REPORT_SIZE - len(report))
                    if not chunk:
                        message = (f"Truncated harness response: {len(report)}/64 bytes"
                                   if report else "Harness closed the response pipe")
                        raise ConnectionFailure(message)
                    report.extend(chunk)
                self._packets.put(bytes(report))
        except Exception as error:
            self._packets.put(error)

    def read_packet(self) -> bytes:
        if self._closed:
            raise ConnectionFailure("Harness connection is closed")
        try:
            packet = self._packets.get(timeout=self.timeout)
        except Empty:
            self.close()
            raise TimeoutError(f"No harness report within {self.timeout:g} seconds") from None
        if isinstance(packet, Exception):
            self.close()
            raise packet
        self.received_reports.append(packet)
        return packet

    def write_packet(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionFailure("Harness connection is closed")
        if len(data) != REPORT_SIZE:
            raise ValueError("HID packets must be exactly 64 bytes, without a report-ID prefix")
        assert self.process.stdin is not None
        try:
            remaining = memoryview(data)
            while remaining:
                written = self.process.stdin.write(remaining)
                if not written:
                    raise ConnectionFailure("Harness accepted an incomplete report write")
                remaining = remaining[written:]
            self.process.stdin.flush()
        except (OSError, ValueError, ConnectionFailure) as error:
            self.close()
            raise ConnectionFailure(f"Cannot write harness report: {error}") from error
        self.sent_reports.append(bytes(data))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.process.stdin is not None:
            self.process.stdin.close()  # EOF allows the C input loop to exit normally.
        try:
            self.process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1.0)
        self._reader.join(timeout=1.0)
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self._presence_directory:
            self._presence_directory.cleanup()

    def _presence_event(self, action: str) -> bool:
        """Simulate a platform touch/denial for the current operation only.

        Private IPC is outside the HID stream and outside the embedded core.
        No request notice means no event is queued or cached for a later request.
        """
        if self._closed or self._presence_directory is None:
            return False
        directory = Path(self._presence_directory.name)
        try:
            operation = int((directory / "request").read_text(encoding="ascii").strip())
        except FileNotFoundError:
            return False
        temporary = directory / "event.tmp"
        temporary.write_text(f"{operation} {action}\n", encoding="ascii")
        temporary.replace(directory / "event")
        return True

    def confirm_presence(self) -> bool:
        return self._presence_event("touch")

    def deny_presence(self) -> bool:
        return self._presence_event("deny")

    def simulated_storage_state(self) -> dict:
        """Inspect volatile test data; no actual credential/PIN features implied."""
        if self._presence_directory is None:
            raise ValueError("Simulation control is disabled")
        return json.loads((Path(self._presence_directory.name) / "factory-state").read_text(encoding="ascii"))

    def __enter__(self) -> HarnessConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def open_harness(executable: str | Path, timeout: float = 5.0, *, user_presence: bool = True) -> CtapHidDevice:
    """Create the standard client; its constructor performs broadcast INIT."""
    descriptor = HidDescriptor(
        path=f"subprocess:{Path(executable).resolve()}", vid=0, pid=0,
        report_size_in=REPORT_SIZE, report_size_out=REPORT_SIZE,
        product_name="CTAPHID C test harness", serial_number=None,
    )
    connection = HarnessConnection(executable, timeout, user_presence=user_presence)
    try:
        return CtapHidDevice(descriptor, connection)
    except BaseException:
        connection.close()
        raise
