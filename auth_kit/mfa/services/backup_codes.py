"""
Backup codes generation service for MFA.

This module provides utilities for generating secure backup codes
that can be used as alternative authentication when primary MFA
methods are unavailable.
"""

from django.utils.crypto import get_random_string


def generate_backup_codes(
    num_of_codes: int, code_length: int, allowed_chars: str
) -> set[str]:
    """
    Generate a set of unique backup codes.

    Creates cryptographically secure backup codes using Django's
    random string generator with specified character set.

    Args:
        num_of_codes: Number of backup codes to generate
        code_length: Length of each backup code
        allowed_chars: Character set for code generation

    Returns:
        Set of unique backup code strings
    """
    return {
        get_random_string(code_length, allowed_chars) for _item in range(num_of_codes)
    }
