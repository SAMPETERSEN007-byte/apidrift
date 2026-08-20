"""Git-backed retrieval of a vendor's OpenAPI spec(s) at two points in time."""
from __future__ import annotations

import datetime as dt
import fnmatch
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .vendors import Vendor


class GitError(RuntimeError):
    pass


class HistoryTooShort(GitError):
    """The repository itself is younger than the requested look-back window.

    Its own state, deliberately not an error and emphatically not a clean
    result. Nothing is broken: the tool correctly has nothing behind the
    window to compare against. Calling it a FAILURE hides a working vendor
    among misconfigured ones; calling it "0 breaking changes" is the false
    all-clear cd1c31e removed at the FILE level, told one level up.

    Carries the date history actually begins so every surface can say how far
    back it CAN see, and the caller can opt into the shorter window on purpose
    rather than being handed one silently.
    """

    def __init__(self, message: str, first_commit_date: str,
                 first_ref: str = "", observable_days: int = 0) -> None:
        super().__init__(message)
        self.first_commit_date = first_commit_date
        self.first_ref = first_ref
        self.observable_days = observable_days


def _run(args: List[str], cwd: Optional[Path] = None, binary: bool = False):
    proc = subprocess.run(
        args, cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise GitError(
            f"$ {' '.join(args[:4])}…\n{proc.stderr.decode('utf-8', 'replace').strip()[:300]}"
        )
    return proc.stdout if binary else proc.stdout.decode("utf-8", "replace").strip()


def _days_between(a: str, b: str) -> int:
    try:
        return (dt.date.fromisoformat(b) - dt.date.fromisoformat(a)).days
    except ValueError:
        return 0


@dataclass
class SpecVersion:
    ref: str
    date: str
    path: str
    raw: bytes


@dataclass
class SpecPair:
    path: str
    old: Optional[SpecVersion]
    new: Optional[SpecVersion]


def ensure_repo(vendor: Vendor, cache_dir: Path, fetch: bool = False) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = cache_dir / vendor.repo.replace("/", "_")
    if not (repo_dir / ".git").is_dir():
        _run(["git", "clone", "--filter=blob:none", "--quiet",
              f"https://github.com/{vendor.repo}", str(repo_dir)])
    elif fetch:
        _run(["git", "fetch", "--quiet", "origin"], cwd=repo_dir)
        _run(["git", "reset", "--hard", "--quiet", "origin/HEAD"], cwd=repo_dir)
    return repo_dir


def head_ref(repo_dir: Path) -> str:
    return _run(["git", "rev-parse", "HEAD"], cwd=repo_dir)


def first_commit(repo_dir: Path) -> str:
    """The oldest commit reachable from HEAD.

    `--max-parents=0` can return several roots when history was grafted or
    merged in; the oldest one is what bounds what this repo can ever show,
    so take the last line `rev-list` prints (it orders newest first).
    """
    roots = _run(["git", "rev-list", "--max-parents=0", "HEAD"],
                 cwd=repo_dir).splitlines()
    if not roots:
        raise GitError("repository has no commits")
    return roots[-1].strip()


def commit_before(repo_dir: Path, date: str) -> str:
    ref = _run(["git", "rev-list", "-1", f"--before={date}", "HEAD"], cwd=repo_dir)
    if not ref:
        root = first_commit(repo_dir)
        began = commit_date(repo_dir, root)
        observable = _days_between(began, commit_date(repo_dir, head_ref(repo_dir)))
        raise HistoryTooShort(
            f"repository history begins {began}, after the window opened at "
            f"{date}; {observable} day(s) are observable. Re-run with "
            f"--days {observable} to diff the range that exists.",
            first_commit_date=began, first_ref=root, observable_days=observable,
        )
    return ref


def commit_date(repo_dir: Path, ref: str) -> str:
    return _run(["git", "show", "-s", "--format=%cd", "--date=short", ref], cwd=repo_dir)


def list_tree(repo_dir: Path, ref: str) -> List[str]:
    return _run(["git", "ls-tree", "-r", "--name-only", ref], cwd=repo_dir).splitlines()


def match_specs(tree: List[str], pattern: str) -> List[str]:
    return sorted(p for p in tree if fnmatch.fnmatch(p, pattern))


def read_blob(repo_dir: Path, ref: str, path: str) -> bytes:
    return _run(["git", "show", f"{ref}:{path}"], cwd=repo_dir, binary=True)


def spec_pairs(
    vendor: Vendor, cache_dir: Path, since_date: str, fetch: bool = False
) -> Tuple[List[SpecPair], Dict[str, str]]:
    """Pair up every spec file matching the vendor's pattern across the window.

    A file present on only one side is returned with the other half `None`,
    which the caller renders as a whole-spec addition or removal.
    """
    repo_dir = ensure_repo(vendor, cache_dir, fetch=fetch)
    new_ref = head_ref(repo_dir)
    old_ref = commit_before(repo_dir, since_date)
    if old_ref == new_ref:
        raise GitError(f"no commits since {since_date}")

    old_paths = match_specs(list_tree(repo_dir, old_ref), vendor.spec_path)
    new_paths = match_specs(list_tree(repo_dir, new_ref), vendor.spec_path)
    if not old_paths and not new_paths:
        raise GitError(f"no file matched pattern '{vendor.spec_path}'")

    old_date, new_date = commit_date(repo_dir, old_ref), commit_date(repo_dir, new_ref)
    pairs: List[SpecPair] = []
    for path in sorted(set(old_paths) | set(new_paths)):
        old_ver = (SpecVersion(old_ref, old_date, path, read_blob(repo_dir, old_ref, path))
                   if path in old_paths else None)
        new_ver = (SpecVersion(new_ref, new_date, path, read_blob(repo_dir, new_ref, path))
                   if path in new_paths else None)
        # Skip files that are byte-identical across the window: nothing to diff.
        if old_ver and new_ver and old_ver.raw == new_ver.raw:
            continue
        pairs.append(SpecPair(path=path, old=old_ver, new=new_ver))

    meta = {"old_ref": old_ref, "new_ref": new_ref,
            "old_date": old_date, "new_date": new_date,
            "specs_matched": str(len(set(old_paths) | set(new_paths))),
            "specs_changed": str(len(pairs))}
    return pairs, meta
