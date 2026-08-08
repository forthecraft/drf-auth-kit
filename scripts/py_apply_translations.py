#!/usr/bin/env python3
# ruff: noqa: C901, PLR0912, PLR0915, PLR2004
"""
Script to apply translated strings back to Django PO files.

This script:
1. Reads translated batch files from temp/translated/
2. Updates the corresponding PO files with translations
3. Preserves all PO file structure and metadata
4. Generates summary of applied translations
"""

import argparse
import json
import sys
from pathlib import Path

import polib

# Language codes (same as extraction script)
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


def load_translated_batch(batch_file_path: Path) -> dict[str, dict[str, str]]:
    """Load a translated batch file.

    New format has language codes as top-level keys with msgid:msgstr dictionaries.
    """
    try:
        with open(batch_file_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading batch file {batch_file_path}: {e}")
        return {}


def apply_translations_to_po(
    lang: str, translations: dict[str, str], force: bool = False
) -> int:
    """Apply translations to a PO file for a specific language.

    Args:
        lang: Language code
        translations: Dictionary mapping msgid to msgstr
        force: If True, overwrite existing translations
    """
    po_file_path = get_po_file_path(lang)

    if not po_file_path.exists():
        print(f"PO file does not exist: {po_file_path}")
        return 0

    try:
        po = polib.pofile(str(po_file_path))
        applied_count = 0

        # Filter out empty translations
        translation_map = {
            msgid: msgstr for msgid, msgstr in translations.items() if msgstr.strip()
        }

        # Apply translations to matching entries
        for entry in po:
            if entry.msgid in translation_map:
                new_translation = translation_map[entry.msgid]

                # Apply translation if:
                # 1. Force mode is on and we have a translation, OR
                # 2. We have a non-empty translation that's different from current
                should_apply = False
                if force and new_translation.strip():
                    should_apply = True
                elif new_translation and new_translation != entry.msgstr:
                    should_apply = True

                if should_apply:
                    entry.msgstr = new_translation

                    # Remove fuzzy flag if the entry was fuzzy and now has a translation
                    if entry.fuzzy and new_translation.strip():
                        if "fuzzy" in entry.flags:
                            entry.flags.remove("fuzzy")
                        # Note: entry.fuzzy is read-only in polib, clearing flags is sufficient

                    applied_count += 1

        # Save the updated PO file
        if applied_count > 0:
            po.save(str(po_file_path))
            print(f"Applied {applied_count} translations to {lang}")

        return applied_count

    except Exception as e:
        print(f"Error applying translations to {lang}: {e}")
        return 0


def get_translated_batch_files() -> list[Path]:
    """Get all translated batch files."""
    translated_dir = Path("temp/translated")

    if not translated_dir.exists():
        print(f"Translated directory does not exist: {translated_dir}")
        return []

    batch_files = list(translated_dir.glob("*.json"))
    if not batch_files:
        print(f"No translated batch files found in {translated_dir}")
        return []

    batch_files.sort()
    return batch_files


def validate_translations(
    translations: dict[str, dict[str, str]],
) -> dict[str, list[str]]:
    """Validate translation data and return issues.

    Args:
        translations: Dictionary with language codes as keys and msgid:msgstr dicts as values

    Returns:
        Dictionary of language codes to lists of validation issues
    """
    issues = {}

    for lang, trans_dict in translations.items():
        lang_issues = []

        if not isinstance(trans_dict, dict):
            lang_issues.append(
                f"Translation data should be a dict, got {type(trans_dict)}"
            )
            continue

        for msgid, msgstr in trans_dict.items():
            if not msgid or not isinstance(msgid, str):
                lang_issues.append(f"Invalid msgid: {repr(msgid)}")

            if not isinstance(msgstr, str):
                lang_issues.append(
                    f"msgstr for '{msgid}' should be string, got {type(msgstr)}"
                )

        if lang_issues:
            issues[lang] = lang_issues

    return issues


def generate_mo_files(languages: set[str]) -> None:
    """Generate MO files for updated languages."""
    print(f"\nGenerating MO files for {len(languages)} languages...")

    for lang in sorted(languages):
        po_file_path = get_po_file_path(lang)
        if po_file_path.exists():
            try:
                po = polib.pofile(str(po_file_path))
                mo_file_path = po_file_path.with_suffix(".mo")
                po.save_as_mofile(str(mo_file_path))
            except Exception as e:
                print(f"Error generating MO file for {lang}: {e}")

    print("MO files generated successfully")


def main():
    """Main function to apply all translations."""
    parser = argparse.ArgumentParser(
        description="Apply translated strings back to Django PO files"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Apply translations even if the entry already has a translation (useful for fuzzy entries)",
    )
    args = parser.parse_args()

    print("Django Translation Applicator")
    print("=" * 40)
    if args.force:
        print("🔧 Force mode enabled - will overwrite existing translations")

    # Check if we're in the right directory
    if not Path("auth_kit").exists():
        print("Error: This script must be run from the project root directory.")
        print("Make sure you're in the directory that contains the 'auth_kit' folder.")
        sys.exit(1)

    # Get all translated batch files
    print("\nStep 1: Finding translated batch files...")
    print("-" * 40)

    batch_files = get_translated_batch_files()
    if not batch_files:
        print(
            "No translated batch files found. Make sure translations are in temp/translated/"
        )
        sys.exit(1)

    print(f"Found {len(batch_files)} translated batch files:")
    for batch_file in batch_files:
        print(f"  - {batch_file.name}")

    # Process each batch file
    print("\nStep 2: Applying translations...")
    print("-" * 40)

    total_applied = 0
    updated_languages = set()
    all_issues = {}

    for batch_file in batch_files:
        print(f"\nProcessing {batch_file.name}...")

        # Load the translated batch
        translations = load_translated_batch(batch_file)
        if not translations:
            print("  Skipping empty or invalid batch file")
            continue

        # Validate translations
        issues = validate_translations(translations)
        if issues:
            all_issues[batch_file.name] = issues
            print("  Warning: Found validation issues (see summary)")

        # Apply translations for each language in the batch
        batch_applied = 0
        for lang, trans_dict in translations.items():
            if lang not in LANGUAGES:
                print(f"  Warning: Unknown language code '{lang}', skipping")
                continue

            applied = apply_translations_to_po(lang, trans_dict, args.force)
            if applied > 0:
                batch_applied += applied
                updated_languages.add(lang)

        if batch_applied > 0:
            print(f"  Applied {batch_applied} translations from this batch")
            total_applied += batch_applied
        else:
            print("  No translations applied from this batch")

    # Generate MO files for updated languages
    if updated_languages:
        print("\nStep 3: Generating MO files...")
        print("-" * 40)
        generate_mo_files(updated_languages)

    # Summary
    print("\nSummary:")
    print("-" * 20)
    print(f"Total translations applied: {total_applied}")
    print(f"Languages updated: {len(updated_languages)}")
    if updated_languages:
        print(f"Updated languages: {', '.join(sorted(updated_languages))}")

    # Report validation issues
    if all_issues:
        print("\nValidation Issues:")
        print("-" * 20)
        for batch_file, lang_issues in all_issues.items():
            print(f"Batch file: {batch_file}")
            for lang, issues in lang_issues.items():
                print(f"  Language '{lang}':")
                for issue in issues[:5]:  # Limit to first 5 issues per language
                    print(f"    - {issue}")
                if len(issues) > 5:
                    print(f"    ... and {len(issues) - 5} more issues")

    if total_applied > 0:
        print("\n✅ Translation application completed successfully!")
        print("Next steps:")
        print("1. Review the updated PO files")
        print("2. Test the application with the new translations")
        print("3. Commit the changes if everything looks good")
    else:
        print("\n⚠️  No translations were applied.")
        print("Please check that:")
        print("1. Translation files contain valid msgstr values")
        print("2. msgid values match those in the PO files")
        print("3. Translation files are properly formatted JSON")


if __name__ == "__main__":
    main()
