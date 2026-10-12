"""Require an explicit reason for every skipped test or collection."""
import os
import pytest

# Stored AgentLAB payload loading uses tokenizers, not local PyTorch inference.
os.environ.setdefault("USE_TORCH", "0")


def _require_skip_reason(report):
    if not report.skipped:
        return
    reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else str(report.longrepr)
    if str(reason).removeprefix('Skipped:').strip() in ('', 'Skipped', 'None'):
        pytest.exit('Skipped test has no explicit reason: ' + report.nodeid, returncode=1)


def pytest_runtest_logreport(report):
    _require_skip_reason(report)


def pytest_collectreport(report):
    _require_skip_reason(report)


def pytest_collection_modifyitems(items):
    for item in items:
        for name in ('skip', 'skipif'):
            for marker in item.iter_markers(name):
                reason = marker.kwargs.get('reason')
                if not isinstance(reason, str) or not reason.strip():
                    raise pytest.UsageError('Skip marker has no explicit reason: ' + item.nodeid)
