#!/usr/bin/env python3
"""Remove juice diagnostics from the current working directory and below.

Usage:
    python3 purge_diag.py --dry-run   # Preview matching paths
    python3 purge_diag.py             # Delete matching paths

Removes directories matching *-diagnostics-* and all their contents, plus
standalone section-*-attempt-*.json, section-*-attempt-*.txt and
section-*-input.md files. Other files, including reports and scripts, are kept.
The scan starts where you run the command, not where this script is saved.
Symbolic links and Windows reparse points (including junctions) are skipped.
Uses only Python's standard library; works on Linux, WSL, macOS and Windows.
"""

import argparse
import fnmatch
import os
from pathlib import Path
import shutil
import stat
import sys


FILE_PATTERNS = (
    'section-*-attempt-*.json',
    'section-*-attempt-*.txt',
    'section-*-input.md',
)


def is_link(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, 'st_file_attributes', 0)
        & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
    )


def checked_target(root, path):
    """Verify the absolute deletion target is below root and traverses no links."""
    relative = path.relative_to(root)
    if not relative.parts:
        raise ValueError('Refusing to remove the current working directory itself')
    current = root
    for part in relative.parts:
        current = current / part
        if is_link(current):
            raise ValueError(f'Refusing to follow a link or reparse point: {current}')
    resolved = path.resolve(strict=True)
    if resolved == root or not resolved.is_relative_to(root):
        raise ValueError(f'Target is outside the scan directory: {resolved}')
    return resolved


def find_targets(root, errors):
    targets = []

    def walk_error(exc):
        errors.append(str(exc))

    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        parent = Path(directory)
        for name in sorted(dirs):
            path = parent / name
            try:
                if is_link(path):
                    dirs.remove(name)
                elif fnmatch.fnmatchcase(name, '*-diagnostics-*'):
                    # Removing the parent will also remove its nested diagnostics.
                    dirs.remove(name)
                    targets.append(('directory', path))
            except OSError as exc:
                dirs.remove(name)
                errors.append(f'{path}: {exc}')
        for name in sorted(files):
            if not any(fnmatch.fnmatchcase(name, pattern) for pattern in FILE_PATTERNS):
                continue
            path = parent / name
            try:
                if not is_link(path) and path.is_file():
                    targets.append(('file', path))
            except OSError as exc:
                errors.append(f'{path}: {exc}')
    return targets


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dry-run', action='store_true', help='List matching paths without deleting anything')
    args = parser.parse_args()
    root = Path.cwd().resolve()
    print(f'Scan directory: {root}')
    errors = []
    targets = find_targets(root, errors)
    counts = {'directory': 0, 'file': 0}
    for kind, path in targets:
        try:
            target = checked_target(root, path)
            if not args.dry_run:
                if kind == 'directory':
                    shutil.rmtree(target)
                else:
                    target.unlink()
            counts[kind] += 1
            print(f'{"Would delete" if args.dry_run else "Deleted"} {kind}: {path.relative_to(root)}')
        except (OSError, ValueError) as exc:
            errors.append(f'{path}: {exc}')
    for error in errors:
        print(f'ERROR: {error}', file=sys.stderr)
    if not targets and not errors:
        print('No matching diagnostics found.')
    action = 'Would remove' if args.dry_run else 'Removed'
    print(f'{action} {counts["directory"]} diagnostic directories (including their contents) '
          f'and {counts["file"]} standalone diagnostic files.')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
