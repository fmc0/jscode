#!/usr/bin/env python3
"""Find juice2/juice3 token diagnostics and print file, run and overall totals.

Usage: python3 token_usage.py [folder] [--summary-only]
With no folder argument, scan the current working directory and all subdirectories.
Print each section-*-attempt-*.json file, grouped by its containing directory.
Use --summary-only to hide individual files and show just totals.
Counts all recorded attempts, including retries and no-findings responses.
Reads native usage keys for Ollama, Bedrock, OpenAI and Anthropic. These are
provider-reported counts, not a billing estimate. Extra cache metrics remain
available in the raw diagnostic JSON; they are not added to these totals.
"""

import argparse
import json
from pathlib import Path


def token_pair(usage):
    if not isinstance(usage, dict):
        return None
    for incoming, outgoing in (
        ('prompt_eval_count', 'eval_count'),  # Ollama
        ('inputTokens', 'outputTokens'),     # Bedrock
        ('prompt_tokens', 'completion_tokens'),  # OpenAI
        ('input_tokens', 'output_tokens'),   # Anthropic
    ):
        values = usage.get(incoming), usage.get(outgoing)
        if all(type(value) is int and value >= 0 for value in values):
            return values
    return None


def summarize(folder):
    files = sorted(folder.glob('section-*-attempt-*.json'))
    if not files:
        raise ValueError(f'No section-*-attempt-*.json files found in {folder}')
    return total_records([read_record(path) for path in files])


def read_record(path):
    record = {'path': path, 'status': 'measured', 'input_tokens': None, 'output_tokens': None}
    try:
        data = json.loads(path.read_text(encoding='utf-8-sig'))
        if not isinstance(data, dict):
            raise ValueError('diagnostic must be a JSON object')
    except (OSError, ValueError) as exc:
        record.update(status='unreadable', error=str(exc))
        return record
    counts = token_pair(data.get('usage'))
    if counts is None:
        record['status'] = 'missing'
    else:
        record['input_tokens'], record['output_tokens'] = counts
    return record


def total_records(records):
    result = dict(files=0, measured=0, missing=0, unreadable=0,
                  input_tokens=0, output_tokens=0)
    for record in records:
        result['files'] += 1
        if record['status'] != 'measured':
            result[record['status']] += 1
            continue
        result['measured'] += 1
        result['input_tokens'] += record['input_tokens']
        result['output_tokens'] += record['output_tokens']
    return result


def print_totals(totals):
    print(f'  Input: {totals["input_tokens"]:,} | Output: {totals["output_tokens"]:,} | '
          f'Total: {totals["input_tokens"] + totals["output_tokens"]:,}')
    print(f'  Files: {totals["files"]:,} | With usage: {totals["measured"]:,} | '
          f'Without usage: {totals["missing"]:,} | Unreadable: {totals["unreadable"]:,}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', nargs='?', default=Path('.'), type=Path,
                        help='Directory to scan recursively (default: current working directory)')
    parser.add_argument('--summary-only', action='store_true', help='Show run totals without individual file rows')
    args = parser.parse_args()
    folder = args.folder.expanduser().resolve()
    if not folder.is_dir():
        parser.error(f'Directory not found: {folder}')
    print(f'Scanning: {folder}')
    groups = {}
    for path in sorted(folder.rglob('section-*-attempt-*.json')):
        if path.is_file() and not path.is_symlink():
            groups.setdefault(path.parent, []).append(read_record(path))
    if not groups:
        print('No section-*-attempt-*.json diagnostic files found in this directory or its subdirectories.')
        return

    for directory, records in groups.items():
        print(f'\nDiagnostics: {directory.relative_to(folder)}')
        if not args.summary_only:
            width = max(15, max(len(record['path'].name) for record in records))
            print(f'{"File":<{width}} {"Input":>12} {"Output":>12} {"Total":>12}  Status')
            for record in records:
                if record['status'] == 'measured':
                    incoming, outgoing = record['input_tokens'], record['output_tokens']
                    values = f'{incoming:>12,} {outgoing:>12,} {incoming + outgoing:>12,}  OK'
                else:
                    label = 'usage unavailable' if record['status'] == 'missing' else 'unreadable JSON'
                    values = f'{"-":>12} {"-":>12} {"-":>12}  {label}'
                print(f'{record["path"].name:<{width}} {values}')
        print('Run totals:')
        print_totals(total_records(records))

    totals = total_records(record for records in groups.values() for record in records)
    print(f'\nOverall totals ({len(groups):,} directories):')
    print_totals(totals)
    if totals['missing'] or totals['unreadable']:
        print('Totals cover only attempts with recorded input and output counts; missing usage is not zero.')


if __name__ == '__main__':
    main()
