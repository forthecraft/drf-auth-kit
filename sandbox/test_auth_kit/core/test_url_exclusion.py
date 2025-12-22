"""Tests for URL exclusion functionality."""

from typing import Any

from django.http import HttpResponse
from django.test import TestCase
from django.urls import URLPattern, re_path

from auth_kit.app_settings import auth_kit_settings
from auth_kit.test_utils import override_auth_kit_settings
from auth_kit.utils import filter_excluded_urls


class TestURLExclusion(TestCase):
    """Test URL exclusion functionality."""

    def test_filter_excluded_urls_empty_list(self) -> None:
        """Test that empty exclusion list returns all patterns."""

        # Create mock patterns that behave like URLPattern objects
        def dummy_view(_: Any) -> HttpResponse:
            return HttpResponse("test")

        mock_patterns = [
            re_path(r"test1/?$", dummy_view, name="test_pattern_1"),
            re_path(r"test2/?$", dummy_view, name="test_pattern_2"),
        ]

        result = filter_excluded_urls(mock_patterns)

        assert len(result) == 2
        assert result == mock_patterns

    @override_auth_kit_settings(EXCLUDED_URL_NAMES=["exclude_pattern"])
    def test_filter_excluded_urls_with_exclusions(self) -> None:
        """Test filtering with exclusions by temporarily modifying settings."""

        def dummy_view(_: Any) -> HttpResponse:
            return HttpResponse("test")

        mock_patterns = [
            re_path(r"keep/?$", dummy_view, name="keep_pattern"),
            re_path(r"exclude/?$", dummy_view, name="exclude_pattern"),
            re_path(r"another/?$", dummy_view, name="another_keep"),
        ]

        # Temporarily modify the EXCLUDED_URL_NAMES
        result = filter_excluded_urls(mock_patterns)

        assert len(result) == 2
        assert isinstance(result[0], URLPattern) and result[0].name == "keep_pattern"
        assert isinstance(result[1], URLPattern) and result[1].name == "another_keep"
        assert all(
            isinstance(pattern, type(mock_patterns[0]))
            and pattern.name != "exclude_pattern"
            for pattern in result
        )

    @override_auth_kit_settings(EXCLUDED_URL_NAMES=["named_pattern"])
    def test_filter_excluded_urls_with_pattern_without_name(self) -> None:
        """Test filtering with patterns that don't have names."""

        def dummy_view(_: Any) -> HttpResponse:
            return HttpResponse("test")

        mock_patterns = [
            re_path(r"named/?$", dummy_view, name="named_pattern"),
            re_path(r"unnamed/?$", dummy_view),  # No name
        ]

        result = filter_excluded_urls(mock_patterns)

        assert len(result) == 1
        assert (
            isinstance(result[0], URLPattern) and result[0].name is None
        )  # The unnamed pattern should remain

    def test_excluded_urls_setting_default(self) -> None:
        """Test that EXCLUDED_URL_NAMES defaults to empty list."""
        assert auth_kit_settings.EXCLUDED_URL_NAMES == []
        assert isinstance(auth_kit_settings.EXCLUDED_URL_NAMES, list)
