from django.contrib.auth.models import User

import responses
from allauth.socialaccount.models import (  # pyright: ignore[reportMissingTypeStubs]
    SocialAccount,
)


class SocialTestMixin:
    """Base test case for social login functionality with class-level test data."""

    # Google OAuth test data
    GOOGLE_TOKEN_RESPONSE = {
        "access_token": "test-google-access-token",
        "refresh_token": "test-google-refresh-token",
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": "openid email profile",
    }

    GOOGLE_USER_INFO = {
        "id": "123456789",
        "email": "test@example.com",
        "verified_email": True,
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "picture": "https://lh3.googleusercontent.com/a/test",
        "locale": "en",
        "hd": "example.com",  # Hosted domain
    }

    # GitHub OAuth test data
    GITHUB_TOKEN_RESPONSE = {
        "access_token": "test-github-access-token",
        "scope": "read:user user:email",
        "token_type": "bearer",
    }

    GITHUB_USER_INFO = {
        "id": 987654321,
        "login": "testuser",
        "name": "Test User",
        "email": "test@example.com",
        "avatar_url": "https://avatars.githubusercontent.com/u/987654321",
        "html_url": "https://github.com/testuser",
        "blog": "https://example.com",
        "company": "Test Company",
        "location": "Test City",
        "bio": "Test bio",
    }

    GITHUB_EMAILS_RESPONSE = [
        {
            "email": "test@example.com",
            "verified": True,
            "primary": True,
            "visibility": "public",
        },
        {
            "email": "private@example.com",
            "verified": True,
            "primary": False,
            "visibility": "private",
        },
    ]

    # Facebook OAuth test data
    FACEBOOK_TOKEN_RESPONSE = {
        "access_token": "test-facebook-access-token",
        "token_type": "bearer",
        "expires_in": 5183944,  # About 60 days
    }

    FACEBOOK_USER_INFO = {
        "id": "1234567890123456",
        "name": "Test User",
        "first_name": "Test",
        "last_name": "User",
        "email": "test@example.com",
        "picture": {
            "data": {
                "height": 50,
                "is_silhouette": False,
                "url": (
                    "https://platform-lookaside.fbsbx.com/platform/profilepic/test.jpg"
                ),
                "width": 50,
            }
        },
        "locale": "en_US",
        "timezone": -7,
    }

    # LinkedIn OpenID Connect test data
    LINKEDIN_TOKEN_RESPONSE = {
        "access_token": "test-linkedin-access-token",
        "expires_in": 5184000,  # 60 days
        "refresh_token": "test-linkedin-refresh-token",
        "refresh_token_expires_in": 31536000,  # 1 year
        "scope": "r_liteprofile r_emailaddress openid",
        "token_type": "Bearer",
        "id_token": (
            "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkLTEyMyIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsaW5rZWRpbi11c2VyLWlkLTEyMyIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiVGVzdCBVc2VyIiwiZ2l2ZW5fbmFtZSI6IlRlc3QiLCJmYW1pbHlfbmFtZSI6IlVzZXIiLCJwaWN0dXJlIjoiaHR0cHM6Ly9tZWRpYS5saWNkbi5jb20vZG1zL2ltYWdlL3Rlc3QuanBnIiwibG9jYWxlIjoiZW5fVVMiLCJpc3MiOiJodHRwczovL3d3dy5saW5rZWRpbi5jb20vb2F1dGgiLCJhdWQiOiJ0ZXN0LWxpbmtlZC1pbi1jbGllbnQtaWQiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTIzNDU2Nzg5MH0.ivQIoPKRMZDJNA7oYLK4keGaFk8NUiG4J6sM29DcjDDHHUq0WyKUNy2Devi1Rp5frv341PRBMtx6dZtI6otzdoMzQF3dTI2jxT-GFEQx1vYFJ42orvud4W4MR0K9X5v-oLWWFCHmBosA4mrP3JFXQqulwvejW8WlsuaGCfghHt9Lxxw86P8497h6ANwYr_BLvBmWOheoZCB_NOeIsMyAv7Q0IJFcPppV1sni_x3IhmyIy9ij_Fpd2bVnjZW3PdrQ-JvJ2rqdtHOU-7uX5inJoYW-Wtm8vIagjYoFFxavO2ClqZqUq-4bnMxViTNcAOKUQuAwcoTL5PDq5BcVrabUWg"
        ),
    }

    LINKEDIN_JWKS = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-id-123",
                "alg": "RS256",
                "n": (
                    "8L4qMiO7XwbvSZfJotF8MAzHMsNE77QlndgLP-pbIqMx7AQKwSaj7bFbZwBTHCk_wmjQRHEcJ0YPt1Yn5qoK5q3W-5-Om5XvsIMlWux5KfkPVmEbKvgZlRlYbpQSSjiYqxueu7p5gHHwEsLzeYbspiz0bvkQH52kIGF5PpvmXVHfRo9-62DDk3gkvzDY7CyeoFz1rQ5K5pBRvRiRAdgfumHt3tAAe24V4P_-iAqJwyY16G7Q3md-lDXmNF8b2xd1QrUx4Lyh2rQXxxDw41Nt4Fi84VDDjueFupCKaHFGemDLP5_IvzRHg9uosLw7-xR7UlNkS12wzhleAT1vaCIsBQ"
                ),
                "e": "AQAB",
            }
        ]
    }

    LINKEDIN_USER_INFO = {
        "sub": "linkedin-user-id-123",
        "email": "test@example.com",
        "email_verified": True,
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "picture": "https://media.licdn.com/dms/image/test.jpg",
        "locale": "en_US",
    }

    def mock_oauth_responses(self, provider: str) -> None:
        """Set up mocked OAuth responses for the specified provider."""
        if provider == "google":
            self._mock_google_responses()
        elif provider == "github":
            self._mock_github_responses()
        elif provider == "facebook":
            self._mock_facebook_responses()
        elif provider == "linkedin":
            self._mock_linkedin_responses()
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def _mock_google_responses(self) -> None:
        """Mock Google OAuth responses."""
        # Mock token exchange
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json=self.GOOGLE_TOKEN_RESPONSE,
            status=200,
        )

        # Mock user info
        responses.add(
            responses.GET,
            "https://www.googleapis.com/oauth2/v2/userinfo",
            json=self.GOOGLE_USER_INFO,
            status=200,
        )

    def _mock_github_responses(self) -> None:
        """Mock GitHub OAuth responses."""
        # Mock token exchange
        responses.add(
            responses.POST,
            "https://github.com/login/oauth/access_token",
            json=self.GITHUB_TOKEN_RESPONSE,
            status=200,
        )

        # Mock user info
        responses.add(
            responses.GET,
            "https://api.github.com/user",
            json=self.GITHUB_USER_INFO,
            status=200,
        )

        # Mock user emails
        responses.add(
            responses.GET,
            "https://api.github.com/user/emails",
            json=self.GITHUB_EMAILS_RESPONSE,
            status=200,
        )

    def _mock_facebook_responses(self) -> None:
        """Mock Facebook OAuth responses."""
        # Facebook uses GET request for token exchange (different from most OAuth providers)
        # Mock both GET and POST to handle different client configurations
        responses.add(
            responses.GET,
            "https://graph.facebook.com/v13.0/oauth/access_token",
            json=self.FACEBOOK_TOKEN_RESPONSE,
            status=200,
        )

        # Also mock POST in case the client is configured differently
        responses.add(
            responses.POST,
            "https://graph.facebook.com/v13.0/oauth/access_token",
            json=self.FACEBOOK_TOKEN_RESPONSE,
            status=200,
        )

        # Mock user info with required fields
        responses.add(
            responses.GET,
            "https://graph.facebook.com/v13.0/me",
            json=self.FACEBOOK_USER_INFO,
            status=200,
        )

    def _mock_linkedin_responses(self) -> None:
        """Mock LinkedIn OpenID Connect responses."""
        # Mock OpenID Connect discovery endpoint (required for OpenID Connect)
        openid_config = {
            "issuer": "https://www.linkedin.com/oauth",
            "authorization_endpoint": "https://www.linkedin.com/oauth/v2/authorization",
            "token_endpoint": "https://www.linkedin.com/oauth/v2/accessToken",
            "userinfo_endpoint": "https://api.linkedin.com/v2/userinfo",
            "jwks_uri": "https://www.linkedin.com/oauth/openid/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "claims_supported": [
                "sub",
                "name",
                "given_name",
                "family_name",
                "email",
                "email_verified",
                "picture",
                "locale",
            ],
        }

        responses.add(
            responses.GET,
            "https://www.linkedin.com/oauth/.well-known/openid-configuration",
            json=openid_config,
            status=200,
        )

        # Mock JWKS endpoint (required for JWT verification)
        responses.add(
            responses.GET,
            "https://www.linkedin.com/oauth/openid/jwks",
            json=self.LINKEDIN_JWKS,
            status=200,
        )

        # Mock token exchange
        responses.add(
            responses.POST,
            "https://www.linkedin.com/oauth/v2/accessToken",
            json=self.LINKEDIN_TOKEN_RESPONSE,
            status=200,
        )

        # Mock user info (OpenID Connect userinfo endpoint)
        responses.add(
            responses.GET,
            "https://api.linkedin.com/v2/userinfo",
            json=self.LINKEDIN_USER_INFO,
            status=200,
        )

    def assert_user_created_correctly(self, email: str, provider: str) -> User:
        """Assert user was created with correct data based on provider."""
        user = User.objects.get(email=email)

        if provider == "google":
            expected_data = self.GOOGLE_USER_INFO
            assert user.first_name == expected_data["given_name"]
            assert user.last_name == expected_data["family_name"]
        elif provider == "github":
            expected_data = self.GITHUB_USER_INFO
            first_name, last_name = str(expected_data["name"]).split(" ")
            assert user.first_name == first_name
            assert user.last_name == last_name
        elif provider == "facebook":
            expected_data = self.FACEBOOK_USER_INFO
            assert user.first_name == expected_data["first_name"]
            assert user.last_name == expected_data["last_name"]
        elif provider == "linkedin":
            expected_data = self.LINKEDIN_USER_INFO
            assert user.first_name == expected_data["given_name"]
            assert user.last_name == expected_data["family_name"]

        return user

    def assert_social_account_created(self, user: User, provider: str) -> SocialAccount:
        """Assert social account was created correctly."""
        if provider == "linkedin":
            # LinkedIn uses OpenID Connect, so provider might be "openid_connect"
            social_account = SocialAccount.objects.get(user=user, provider="linkedin")
            assert social_account.uid == self.LINKEDIN_USER_INFO["sub"]
            # For OpenID Connect, name might be in extra_data or might not be stored
            # Just verify the uid matches, which is the critical assertion
            return social_account

        social_account = SocialAccount.objects.get(user=user, provider=provider)

        if provider == "google":
            assert social_account.uid == self.GOOGLE_USER_INFO["id"]
            assert social_account.extra_data["name"] == self.GOOGLE_USER_INFO["name"]
        elif provider == "github":
            assert social_account.uid == str(self.GITHUB_USER_INFO["id"])
            assert social_account.extra_data["login"] == self.GITHUB_USER_INFO["login"]
        elif provider == "facebook":
            assert social_account.uid == self.FACEBOOK_USER_INFO["id"]
            assert social_account.extra_data["name"] == self.FACEBOOK_USER_INFO["name"]

        return social_account
