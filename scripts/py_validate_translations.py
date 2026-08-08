#!/usr/bin/env python3
# ruff: noqa: C901, PLR0912, PLR0915, PLR2004
"""
Script to validate that all untranslated strings in PO files have
corresponding translations in the translated folder.

This script:
1. Extracts all untranslated strings from PO files
2. Loads all translations from temp/translated/ folder
3. Reports missing translations and coverage statistics
4. Identifies extra translations that don't match any PO entries
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import polib

# Language codes for translation
LANGUAGES = [
    "af",
    "ar",
    "az",
    "be",
    "bg",
    "bs",
    "ca",
    "cs",
    "cy",
    "da",
    "de",
    "el",
    "es",
    "et",
    "fa",
    "fi",
    "fr",
    "gl",
    "he",
    "hi",
    "hr",
    "hu",
    "hy",
    "id",
    "is",
    "it",
    "ja",
    "kk",
    "kn",
    "ko",
    "lt",
    "lv",
    "mi",
    "mk",
    "mr",
    "ms",
    "ne",
    "nl",
    "no",
    "pl",
    "pt",
    "ro",
    "ru",
    "sk",
    "sl",
    "sr",
    "sv",
    "sw",
    "ta",
    "th",
    "tl",
    "tr",
    "uk",
    "ur",
    "vi",
    "zh",
]


def get_po_file_path(lang: str) -> Path:
    """Get the path to the PO file for a given language."""
    return Path(f"auth_kit/locale/{lang}/LC_MESSAGES/django.po")


def extract_untranslated_from_po(lang: str) -> set[str]:
    """Extract untranslated msgids from a PO file."""
    po_file_path = get_po_file_path(lang)

    if not po_file_path.exists():
        return set()

    try:
        po = polib.pofile(str(po_file_path))
        untranslated = set()

        for entry in po.untranslated_entries():
            if entry.msgid and entry.msgid.strip():
                untranslated.add(entry.msgid)

        return untranslated

    except Exception as e:
        print(f"Error extracting from {po_file_path}: {e}")
        return set()


def load_translations_from_batch_files() -> dict[str, dict[str, str]]:
    """Load all translations from batch files in temp/translated/.

    New format has language codes as top-level keys with msgid:msgstr dictionaries.
    The 'raw' key is skipped as it contains the source English text.
    """
    translated_dir = Path("temp/translated")

    if not translated_dir.exists():
        print(f"Translated directory does not exist: {translated_dir}")
        return {}

    all_translations = {}
    batch_files = list(translated_dir.glob("*.json"))

    for batch_file in batch_files:
        try:
            with open(batch_file, encoding="utf-8") as f:
                batch_data = json.load(f)

            for lang, translations in batch_data.items():
                # Skip the 'raw' key as it contains source text, not translations
                if lang == "raw":
                    continue

                if lang not in all_translations:
                    all_translations[lang] = {}

                # In the new format, translations is already a dict of msgid:msgstr
                if isinstance(translations, dict):
                    all_translations[lang].update(translations)

        except Exception as e:
            print(f"Error loading {batch_file}: {e}")

    return all_translations


def validate_language_coverage(
    lang: str, po_untranslated: set[str], translations: dict[str, str]
) -> dict[str, any]:
    """Validate translation coverage for a single language."""

    # Find missing translations
    missing = po_untranslated - set(translations.keys())

    # Find translations with empty msgstr
    empty_translations = {
        msgid for msgid, msgstr in translations.items() if not msgstr.strip()
    }

    # Find extra translations (not in PO file)
    extra = set(translations.keys()) - po_untranslated

    # Calculate coverage
    total_needed = len(po_untranslated)
    provided = len(set(translations.keys()) & po_untranslated)
    with_content = len(
        {
            msgid
            for msgid in set(translations.keys()) & po_untranslated
            if translations[msgid].strip()
        }
    )

    coverage_rate = (provided / total_needed * 100) if total_needed > 0 else 100
    content_rate = (with_content / total_needed * 100) if total_needed > 0 else 100

    return {
        "total_needed": total_needed,
        "provided": provided,
        "with_content": with_content,
        "missing": missing,
        "empty_translations": empty_translations,
        "extra": extra,
        "coverage_rate": coverage_rate,
        "content_rate": content_rate,
    }


def print_language_report(lang: str, stats: dict[str, any], show_details: bool = False):
    """Print detailed report for a single language."""
    print(f"\n📋 Language: {lang.upper()}")
    print(f"   Total needed: {stats['total_needed']}")
    print(f"   Provided: {stats['provided']} ({stats['coverage_rate']:.1f}%)")
    print(f"   With content: {stats['with_content']} ({stats['content_rate']:.1f}%)")

    if stats["missing"]:
        print(f"   ❌ Missing: {len(stats['missing'])}")
        if show_details and len(stats["missing"]) <= 10:
            for msgid in sorted(list(stats["missing"])[:10]):
                print(f"      • {msgid[:60]}...")
        elif show_details:
            print(
                f"      • {len(stats['missing'])} missing entries (first 10 shown above)"
            )

    if stats["empty_translations"]:
        print(f"   ⚠️  Empty: {len(stats['empty_translations'])}")
        if show_details and len(stats["empty_translations"]) <= 5:
            for msgid in sorted(list(stats["empty_translations"])[:5]):
                print(f"      • {msgid[:60]}...")

    if stats["extra"]:
        print(f"   ➕ Extra: {len(stats['extra'])}")
        if show_details and len(stats["extra"]) <= 5:
            for msgid in sorted(list(stats["extra"])[:5]):
                print(f"      • {msgid[:60]}...")


def main():
    """Main validation function."""
    import argparse

    parser = argparse.ArgumentParser(description="Validate translation coverage")
    parser.add_argument(
        "--details", action="store_true", help="Show detailed missing/extra entries"
    )
    parser.add_argument(
        "--language", "-l", help="Validate only specific language (e.g., 'pt', 'fr')"
    )
    parser.add_argument(
        "--summary-only", action="store_true", help="Show only summary statistics"
    )
    args = parser.parse_args()

    print("Translation Coverage Validator")
    print("=" * 50)

    # Check if we're in the right directory
    if not Path("auth_kit").exists():
        print("Error: This script must be run from the project root directory.")
        print("Make sure you're in the directory that contains the 'auth_kit' folder.")
        sys.exit(1)

    # Load all translations
    print("\n📂 Loading translations from batch files...")
    all_translations = load_translations_from_batch_files()

    if not all_translations:
        print("❌ No translations found in temp/translated/")
        sys.exit(1)

    print(f"   Found translations for {len(all_translations)} languages")

    # Validate languages
    languages_to_check = [args.language] if args.language else LANGUAGES
    if args.language and args.language not in LANGUAGES:
        print(f"⚠️  Warning: '{args.language}' is not in the standard language list")

    total_stats = {
        "languages_checked": 0,
        "total_needed": 0,
        "total_provided": 0,
        "total_with_content": 0,
        "languages_complete": 0,
        "languages_with_translations": 0,
    }

    print(f"\n🔍 Validating {len(languages_to_check)} languages...")
    print("-" * 50)

    for lang in languages_to_check:
        po_untranslated = extract_untranslated_from_po(lang)

        if not po_untranslated:
            if not args.summary_only:
                print(f"\n✅ Language: {lang.upper()} - No untranslated strings")
            continue

        translations = all_translations.get(lang, {})
        stats = validate_language_coverage(lang, po_untranslated, translations)

        # Update totals
        total_stats["languages_checked"] += 1
        total_stats["total_needed"] += stats["total_needed"]
        total_stats["total_provided"] += stats["provided"]
        total_stats["total_with_content"] += stats["with_content"]

        if stats["coverage_rate"] == 100:
            total_stats["languages_complete"] += 1
        if stats["provided"] > 0:
            total_stats["languages_with_translations"] += 1

        if not args.summary_only:
            print_language_report(lang, stats, args.details)

    # Print summary
    print("\n📊 SUMMARY")
    print("=" * 30)
    print(f"Languages checked: {total_stats['languages_checked']}")
    print(f"Languages with translations: {total_stats['languages_with_translations']}")
    print(f"Languages complete (100%): {total_stats['languages_complete']}")

    if total_stats["total_needed"] > 0:
        overall_coverage = (
            total_stats["total_provided"] / total_stats["total_needed"]
        ) * 100
        overall_content = (
            total_stats["total_with_content"] / total_stats["total_needed"]
        ) * 100

        print("\nOverall Statistics:")
        print(f"  Total strings needed: {total_stats['total_needed']:,}")
        print(
            f"  Total provided: {total_stats['total_provided']:,} ({overall_coverage:.1f}%)"
        )
        print(
            f"  Total with content: {total_stats['total_with_content']:,} ({overall_content:.1f}%)"
        )
        print(
            f"  Missing translations: {total_stats['total_needed'] - total_stats['total_provided']:,}"
        )

        # Status indicator
        if overall_content >= 95:
            print(f"\n🎉 Translation status: EXCELLENT ({overall_content:.1f}%)")
        elif overall_content >= 80:
            print(f"\n✅ Translation status: GOOD ({overall_content:.1f}%)")
        elif overall_content >= 50:
            print(f"\n⚠️  Translation status: FAIR ({overall_content:.1f}%)")
        else:
            print(f"\n❌ Translation status: NEEDS WORK ({overall_content:.1f}%)")
    else:
        print("\n🎉 All languages are fully translated!")


if __name__ == "__main__":
    main()
