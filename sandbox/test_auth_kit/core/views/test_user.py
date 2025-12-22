from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from test_utils.user_factory import UserFactory

User = get_user_model()


class TestUserView(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("rest_user")

    def test_get_user_details_unauthenticated(self) -> None:
        """Test retrieving user details without authentication"""
        response: Response = self.client.get(self.url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_user_details_success(self) -> None:
        """Test successful retrieval of user details"""
        self.client.force_authenticate(user=self.user)

        response: Response = self.client.get(self.url)

        assert response.status_code == status.HTTP_200_OK

        # Check that user data is returned
        assert response.data["username"] == "testuser"
        assert response.data["email"] == "test@example.com"
        assert "pk" in response.data
        assert response.data["pk"] == self.user.pk

    def test_get_user_details_with_first_last_name(self) -> None:
        """Test user details retrieval with first and last name"""
        # Update user with first and last name
        self.user.first_name = "Test"
        self.user.last_name = "User"
        self.user.save()

        self.client.force_authenticate(user=self.user)

        response: Response = self.client.get(self.url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["first_name"] == "Test"
        assert response.data["last_name"] == "User"

    def test_put_user_details_unauthenticated(self) -> None:
        """Test updating user details without authentication"""
        data = {"username": "newusername"}
        response: Response = self.client.put(self.url, data, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_put_user_details_success(self) -> None:
        """Test successful full update of user details"""
        self.client.force_authenticate(user=self.user)

        data = {
            "username": "newusername",
            "first_name": "New",
            "last_name": "Name",
        }

        response: Response = self.client.put(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == "newusername"
        assert response.data["first_name"] == "New"
        assert response.data["last_name"] == "Name"

        # Verify changes in database
        self.user.refresh_from_db()
        assert self.user.username == "newusername"
        assert self.user.first_name == "New"
        assert self.user.last_name == "Name"

    def test_patch_user_details_success(self) -> None:
        """Test successful partial update of user details"""
        self.client.force_authenticate(user=self.user)

        data = {"first_name": "Updated"}

        response: Response = self.client.patch(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["first_name"] == "Updated"
        assert response.data["username"] == "testuser"  # Should remain unchanged

        # Verify changes in database
        self.user.refresh_from_db()
        assert self.user.first_name == "Updated"
        assert self.user.username == "testuser"

    def test_patch_user_details_username_only(self) -> None:
        """Test partial update of username only"""
        self.client.force_authenticate(user=self.user)

        data = {"username": "updateduser"}

        response: Response = self.client.patch(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == "updateduser"

        # Verify changes in database
        self.user.refresh_from_db()
        assert self.user.username == "updateduser"

    def test_email_is_read_only(self) -> None:
        """Test that email field is read-only"""
        self.client.force_authenticate(user=self.user)

        original_email = self.user.email
        data = {
            "username": "updatedusername",  # Change username to avoid conflict
            "email": "newemail@example.com",  # Try to change email
            "first_name": "Test",
        }

        response: Response = self.client.put(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        # Email should not change
        assert response.data["email"] == original_email

        # Verify email didn't change in database
        self.user.refresh_from_db()
        assert self.user.email == original_email

    def test_put_missing_required_fields(self) -> None:
        """Test PUT request with missing required fields"""
        self.client.force_authenticate(user=self.user)

        # PUT requires all fields, missing username
        data = {
            "first_name": "Test",
            "last_name": "User",
        }

        response: Response = self.client.put(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "username" in response.data

    def test_invalid_username_validation(self) -> None:
        """Test username validation using allauth adapter"""
        self.client.force_authenticate(user=self.user)

        # Test with empty username
        data = {
            "username": "",
            "first_name": "Test",
        }

        response: Response = self.client.patch(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "username" in response.data

    def test_duplicate_username(self) -> None:
        """Test updating to an existing username"""
        # Create another user
        other_user_data = {
            "username": "otheruser",
            "email": "other@example.com",
            "password": "password123",
        }
        UserFactory.create_with_email_address(other_user_data)

        self.client.force_authenticate(user=self.user)

        # Try to update to existing username
        data = {"username": "otheruser"}

        response: Response = self.client.patch(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "username" in response.data

    def test_get_user_details_returns_correct_fields(self) -> None:
        """Test that GET returns only expected fields"""
        # Set all possible user fields
        self.user.first_name = "Test"
        self.user.last_name = "User"
        self.user.save()

        self.client.force_authenticate(user=self.user)

        response: Response = self.client.get(self.url)

        assert response.status_code == status.HTTP_200_OK

        # Check expected fields are present
        expected_fields = {"pk", "username", "email", "first_name", "last_name"}
        actual_fields = set(response.data.keys())

        # All expected fields should be present
        assert expected_fields.issubset(actual_fields)

        # Sensitive fields should not be present
        sensitive_fields = {"password", "is_staff", "is_superuser", "user_permissions"}
        assert not any(field in actual_fields for field in sensitive_fields)

    def test_delete_method_not_allowed(self) -> None:
        """Test that DELETE method is not allowed"""
        self.client.force_authenticate(user=self.user)

        response: Response = self.client.delete(self.url)

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_post_method_not_allowed(self) -> None:
        """Test that POST method is not allowed"""
        self.client.force_authenticate(user=self.user)

        data = {"username": "newuser"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_get_object_returns_authenticated_user(self) -> None:
        """Test that get_object returns the authenticated user"""
        # Create another user
        other_user_data = {
            "username": "otheruser",
            "email": "other@example.com",
            "password": "password123",
        }
        UserFactory.create_with_email_address(other_user_data)

        # Authenticate as first user
        self.client.force_authenticate(user=self.user)

        response: Response = self.client.get(self.url)

        assert response.status_code == status.HTTP_200_OK
        # Should return data for authenticated user, not the other user
        assert response.data["pk"] == self.user.pk
        assert response.data["username"] == "testuser"

    def test_patch_empty_string_fields(self) -> None:
        """Test PATCH with empty string values for name fields"""
        # Set initial values
        self.user.first_name = "Initial"
        self.user.last_name = "Name"
        self.user.save()

        self.client.force_authenticate(user=self.user)

        data = {
            "first_name": "",
            "last_name": "",
        }

        response: Response = self.client.patch(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["first_name"] == ""
        assert response.data["last_name"] == ""

        # Verify changes in database
        self.user.refresh_from_db()
        assert self.user.first_name == ""
        assert self.user.last_name == ""

    def test_patch_with_same_username(self) -> None:
        """Test PATCH with user's current username should succeed"""
        self.client.force_authenticate(user=self.user)

        # Try to update with same username (should not raise uniqueness error)
        data = {
            "username": "testuser",  # Same as current username
            "first_name": "Updated",
        }

        response: Response = self.client.patch(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == "testuser"
        assert response.data["first_name"] == "Updated"

        # Verify changes in database
        self.user.refresh_from_db()
        assert self.user.username == "testuser"
        assert self.user.first_name == "Updated"

    def test_put_with_same_username(self) -> None:
        """Test PUT with user's current username should succeed"""
        self.client.force_authenticate(user=self.user)

        # Try to update with same username (should not raise uniqueness error)
        data = {
            "username": "testuser",  # Same as current username
            "first_name": "Updated",
            "last_name": "User",
        }

        response: Response = self.client.put(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == "testuser"
        assert response.data["first_name"] == "Updated"
        assert response.data["last_name"] == "User"

        # Verify changes in database
        self.user.refresh_from_db()
        assert self.user.username == "testuser"
        assert self.user.first_name == "Updated"
        assert self.user.last_name == "User"


class TestUserViewEdgeCases(APITestCase):
    """Test edge cases for user details view"""

    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("rest_user")

    def test_get_queryset_returns_empty(self) -> None:
        """Test that get_queryset returns empty queryset"""
        from auth_kit.views.user import UserView

        view = UserView()
        queryset = view.get_queryset()

        assert queryset.count() == 0
        assert not queryset.exists()

    def test_partial_update_preserves_other_fields(self) -> None:
        """Test that PATCH preserves fields not being updated"""
        # Set initial values
        self.user.first_name = "Original"
        self.user.last_name = "Name"
        self.user.save()

        self.client.force_authenticate(user=self.user)

        # Only update first_name
        data = {"first_name": "Updated"}
        response: Response = self.client.patch(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["first_name"] == "Updated"
        assert response.data["last_name"] == "Name"  # Should remain unchanged
        assert response.data["username"] == "testuser"  # Should remain unchanged
