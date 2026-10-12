import pytest

from governance_substrate.substrate import path_protected

PATTERNS = [".env*", "*.key", "*credentials*", "private/"]


@pytest.mark.parametrize("path", [
    ".env", "sub/.env", ".env.local", "a/.ENV", "a/b/x.key", "server.KEY",
    "Credentials.json", "a/aws-credentials", "private/notes.txt"])
def test_protected_variants_are_denied(path):
    assert path_protected(path, PATTERNS)


@pytest.mark.parametrize("path", ["review-status.txt", "notes/env.txt", "keys.txt", "privately/a.txt"])
def test_ordinary_paths_are_allowed(path):
    assert not path_protected(path, PATTERNS)


def test_exact_names_still_match_at_any_depth():
    assert path_protected("protected.txt", ["protected.txt"])
    assert path_protected("a/protected.txt", ["protected.txt"])
    assert not path_protected("protected.txt.bak", ["protected.txt"])
