"""Seed corpus management for vulnerability-class-aware fuzzing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _find_seeds_dir() -> Path:
    repo_seeds = Path(__file__).resolve().parents[4] / "data" / "seeds"
    if repo_seeds.is_dir():
        return repo_seeds
    cwd_seeds = Path("data/seeds")
    if cwd_seeds.is_dir():
        return cwd_seeds
    return repo_seeds


def get_seed_file(vuln_class: str, seeds_dir: Path | None = None) -> Path | None:
    if not vuln_class:
        return None
    if seeds_dir is None:
        seeds_dir = _find_seeds_dir()
    norm = vuln_class.lower().replace("-", "_").replace(" ", "_")
    if "cmd" in norm or "command" in norm:
        target = seeds_dir / "cmd_injection_seeds.json"
    elif "proto" in norm:
        target = seeds_dir / "proto_pollution_seeds.json"
    elif "path" in norm or "traversal" in norm:
        target = seeds_dir / "path_traversal_seeds.json"
    elif "redos" in norm or "regex" in norm:
        target = seeds_dir / "redos_seeds.json"
    else:
        target = None
    return target if (target and target.is_file()) else None


def seed_corpus(corpus_dir: Path, vuln_class: str, seeds_dir: Path | None = None) -> int:
    """Seed the Jazzer corpus directory with vulnerability-class-specific trigger patterns.

    Writes each seed as its own file under corpus_dir/ (filename = sha1(seed)[:12])
    and returns the count written.
    """
    if not vuln_class:
        return 0
    seed_file = get_seed_file(vuln_class, seeds_dir)
    if not seed_file or not seed_file.is_file():
        return 0
    try:
        data = json.loads(seed_file.read_text(encoding="utf-8"))
    except Exception:
        return 0
    seeds = data.get("seeds", [])
    if not seeds:
        return 0

    corpus_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for seed in seeds:
        if not isinstance(seed, str):
            continue
        encoded = seed.encode("utf-8")
        filename = hashlib.sha1(encoded).hexdigest()[:12]
        (corpus_dir / filename).write_bytes(encoded)
        count += 1
    return count
