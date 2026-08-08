#!/usr/bin/env python
# ruff: noqa: C901
"""
Script to clean and extract untranslated strings from Django PO files.

This script:
1. Removes outdated/unused translations (marked with #~)
2. Extracts strings that haven't been translated yet (empty msgstr)
3. Creates batch files for translation in JSON format
"""

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

BATCH_SIZE = 4


def get_po_file_path(lang: str) -> Path:
    """Get the path to the PO file for a given language."""
    return Path(f"auth_kit/locale/{lang}/LC_MESSAGES/django.po")


def clean_po_file(po_file_path: Path) -> None:
    """Remove outdated/unused translations and clean fuzzy entries from a PO file."""
    if not po_file_path.exists():
        return

    try:
        po = polib.pofile(str(po_file_path))

        # Count obsolete entries before removal
        obsolete_count = len(po.obsolete_entries())

        # Process fuzzy entries - clear msgstr, remove fuzzy flag and previous_msgid
        fuzzy_count = 0
        for entry in po:
            if "fuzzy" in entry.flags:
                # Clear the translation (it's based on wrong previous msgid)
                entry.msgstr = ""
                # Remove fuzzy flag
                entry.flags.remove("fuzzy")
                # Clear previous_msgid
                entry.previous_msgid = None
                entry.previous_msgid_plural = None
                entry.previous_msgctxt = None
                fuzzy_count += 1

        # Save the file if we processed any fuzzy entries
        if fuzzy_count > 0:
            po.save()
            print(f"Cleaned {po_file_path.name}: cleared {fuzzy_count} fuzzy entries")

        # Remove obsolete entries (marked with #~) by directly manipulating the file
        if obsolete_count > 0:
            # Read the file content
            with open(po_file_path, encoding="utf-8") as f:
                content = f.read()

            # Split into lines for processing
            lines = content.split("\n")
            cleaned_lines = []
            i = 0

            while i < len(lines):
                line = lines[i]

                # Check if this is the start of an obsolete entry
                if line.startswith("#~ "):
                    # Skip this obsolete entry - consume until next entry or EOF
                    while i < len(lines) and (
                        lines[i].startswith("#~ ") or lines[i] == ""
                    ):
                        i += 1
                    continue
                else:
                    # Keep this line
                    cleaned_lines.append(line)
                    i += 1

            # Write the cleaned content back
            cleaned_content = "\n".join(cleaned_lines)
            with open(po_file_path, "w", encoding="utf-8") as f:
                f.write(cleaned_content)

            print(
                f"Cleaned {po_file_path.name}: removed {obsolete_count} obsolete entries"
            )

        if obsolete_count == 0 and fuzzy_count == 0:
            print(f"No obsolete or fuzzy entries in {po_file_path.name}")

    except Exception as e:
        print(f"Error cleaning {po_file_path.name}: {e}")


def extract_untranslated_strings(lang: str) -> dict[str, str]:
    """Extract untranslated strings from a language's PO file.

    Returns a dictionary with msgid as key and empty string as value.
    """
    po_file_path = get_po_file_path(lang)

    if not po_file_path.exists():
        return {}

    try:
        po = polib.pofile(str(po_file_path))
        untranslated = {}

        # Get untranslated entries (empty msgstr)
        untranslated_entries = po.untranslated_entries()

        # Process untranslated entries
        for entry in untranslated_entries:
            # Skip empty msgids and header entries
            if entry.msgid and entry.msgid.strip():
                untranslated[entry.msgid] = ""

        if untranslated:
            print(f"Found {len(untranslated)} untranslated strings for {lang}")

        return untranslated

    except Exception as e:
        print(f"Error extracting from {po_file_path}: {e}")
        return {}


def create_batch_files(extraction_data: dict[str, dict[str, str]]) -> None:
    """Create batch files for translation with new format.

    The new format has language codes as top-level keys, each containing
    msgid:empty-string dictionaries to be filled with translations.
    """
    # Create temp/extracted directory
    extracted_dir = Path("temp/extracted")
    extracted_dir.mkdir(parents=True, exist_ok=True)

    # Filter languages that have untranslated strings
    languages_with_work = {lang: data for lang, data in extraction_data.items() if data}

    if not languages_with_work:
        print("No untranslated strings found across all languages.")
        return

    # Create batches of languages
    lang_list = list(languages_with_work.keys())
    batches = [
        lang_list[i : i + BATCH_SIZE] for i in range(0, len(lang_list), BATCH_SIZE)
    ]

    for batch in batches:
        # Create batch filename
        batch_filename = "-".join(batch) + ".json"
        batch_path = extracted_dir / batch_filename

        # Create batch data structure with new format
        batch_data = {}

        for lang in batch:
            if lang in languages_with_work:
                # Each language gets empty strings for translation
                batch_data[lang] = languages_with_work[lang]

        # Save batch file
        with open(batch_path, "w", encoding="utf-8") as f:
            json.dump(batch_data, f, indent=2, ensure_ascii=False)

        total_strings = sum(len(data) for data in batch_data.values())
        print(
            f"Created batch file: {batch_filename} with {total_strings} strings for {len(batch)} languages"
        )


def main():
    """Main function to clean and extract translations."""
    print("Django Translation Extractor")
    print("=" * 40)

    # Check if we're in the right directory
    if not Path("auth_kit").exists():
        print("Error: This script must be run from the project root directory.")
        print("Make sure you're in the directory that contains the 'auth_kit' folder.")
        sys.exit(1)

    # Step 1: Clean all PO files
    print("\nStep 1: Cleaning PO files...")
    print("-" * 30)

    for lang in LANGUAGES:
        po_file_path = get_po_file_path(lang)
        if po_file_path.exists():
            clean_po_file(po_file_path)

    # Step 2: Extract untranslated strings
    print("\nStep 2: Extracting untranslated strings...")
    print("-" * 40)

    extraction_data = {}
    total_untranslated = 0

    for lang in LANGUAGES:
        untranslated = extract_untranslated_strings(lang)
        if untranslated:
            extraction_data[lang] = untranslated
            total_untranslated += len(untranslated)

    print(f"\nTotal untranslated strings: {total_untranslated}")
    print(f"Languages with untranslated strings: {len(extraction_data)}")

    # Step 3: Create batch files
    print("\nStep 3: Creating batch files...")
    print("-" * 30)

    create_batch_files(extraction_data)

    print(
        "\nExtraction complete! Check the 'temp/extracted/' directory for batch files."
    )

    if extraction_data:
        print("\nNext steps:")
        print("1. Use the translation prompt to translate the batch files")
        print("2. Run the application script to apply translations back to PO files")
    else:
        print("\nAll translations are up to date! 🎉")


if __name__ == "__main__":
    main()
