#!/usr/bin/env python3
"""Apply simple placeholder replacements to an Ozark Security Labs template repo."""

from __future__ import annotations

import argparse
from pathlib import Path

TEXT_SUFFIXES = {
    '.md', '.yml', '.yaml', '.toml', '.json', '.txt', '.gitignore', '.gitattributes', '.editorconfig', '.py'
}


def is_text(path: Path) -> bool:
    return path.suffix in TEXT_SUFFIXES or path.name in {'.gitignore', '.gitattributes', '.editorconfig'}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', required=True)
    parser.add_argument('--slug', required=True)
    parser.add_argument('--description', required=True)
    parser.add_argument('--language', default='unspecified')
    parser.add_argument('--contact', default='GitHub private vulnerability reporting')
    parser.add_argument('--root', default='.')
    args = parser.parse_args()

    replacements = {
        'PROJECT_NAME': args.name,
        'PROJECT_SLUG': args.slug,
        'PROJECT_DESCRIPTION': args.description,
        'PRIMARY_LANGUAGE': args.language,
        'CONTACT_METHOD': args.contact,
    }

    root = Path(args.root).resolve()
    for path in root.rglob('*'):
        if '.git' in path.parts or not path.is_file() or not is_text(path):
            continue
        text = path.read_text(encoding='utf-8')
        new = text
        for old, value in replacements.items():
            new = new.replace(old, value)
        if new != text:
            path.write_text(new, encoding='utf-8')
            print(path.relative_to(root))

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
