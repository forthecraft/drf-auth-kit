## v0.3.8 (2025-09-09)

### Fix

- correct django-allauth package constraint due to error

## v0.3.7 (2025-09-09)

### Fix

- **docs**: correct token refresh documentation to clarify manual API calls required

## v0.3.6 (2025-08-14)

### Fix

- remove types-python-dateutil dev package

## v0.3.5 (2025-08-14)

### Fix

- **auth**: simplify cookie handling and remove dateutil parser usage

## v0.3.4 (2025-08-10)

### Fix

- **compat**: add backward compatibility for untyped Django usage

## v0.3.3 (2025-08-09)

### Fix

- **jwt**: add dateutil parser import and type support for cookie expiration

## v0.3.2 (2025-07-22)

### Fix

- **password**: disable authentication for password reset confirm view

## v0.3.1 (2025-07-21)

### Fix

- **docs**: correct configuration examples and version requirements

## v0.3.0 (2025-07-21)

### Feat

- **urls**: add flexible frontend URL configuration for email verification and password reset

## v0.2.9 (2025-07-17)

### Fix

- **types**: add pyright to lint section of tox and fix some minor type errors
- **auth_kit**: rename user details view and serializer for better api doc

## v0.2.8 (2025-07-17)

### Fix

- **SocialAccountViewSet**: update get_queryset to use user_id to prevent drf_spectacular raise exception

## v0.2.7 (2025-07-12)

### Fix

- **registration**: include first_name and last_name in cleaned registration data

## v0.2.6 (2025-07-12)

### Fix

- **social**: update type hint for social_urls

## v0.2.5 (2025-07-12)

### Fix

- **social**: handle database unavailability during URL generation

## v0.2.4 (2025-07-12)

### Fix

- **serializers**: add _has_phone_field property to RegisterSerializer

## v0.2.3 (2025-07-12)

### Fix

- **dependencies**: loosen version for drf spectacular and structlog

## v0.2.2 (2025-07-09)

### Fix

- **roadmap**: add upcoming features documentation and roadmap
- **contributing**: update development workflow and testing practices

## v0.2.1 (2025-07-09)

### Fix

- **rtd**: install all extras for building readthedocs

## v0.2.0 (2025-07-09)

### Feat

- **auth**: enhance registration, user validation, and error handling
- **i18n**: add internationalization support with 50+ language locales
- **urls**: add URL exclusion functionality via EXCLUDED_URL_NAMES setting
- **auth**: add login redirect support with next and redirect_to parameters
- **mfa**: improved internationalization support and type safety
- **mfa**: add i18n support and comprehensive API documentation
- **mfa**: add multi-factor authentication support
- **social**: add comprehensive social authentication support with django-allauth integration
- **tests**: add comprehensive test suite and sandbox examples
- **serializers**: add dynamic serializer loading and improved authentication

### Fix

- **api**: correct registration descriptions and add missing i18n for social auth
- **package**: update package dependencies
- **rtd**: ignore building docs if the commit message is not bump version
- **coverage**: export xml for cov report

## v0.1.1 (2025-06-19)

### Fix

- **pyproject**: rename package from auth_kit to drf-auth-kit

## v0.1.0 (2025-06-19)

### Feat

- **auth**: implement complete DRF authentication kit with JWT, token, and custom auth support
- **setup**: initialize project
