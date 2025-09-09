Introduction
============

DRF Auth Kit is a modern Django REST Framework authentication toolkit that provides a complete authentication solution with JWT cookies, social login, multi-factor authentication (MFA), and comprehensive user management.

Why Choose DRF Auth Kit?
~~~~~~~~~~~~~~~~~~~~~~~~~

**Built for Modern Development**

DRF Auth Kit addresses the limitations of existing authentication packages by providing:

- **Complete Type Safety**: Full type hints with mypy and pyright compatibility
- **OpenAPI Integration**: Automatic schema generation with DRF Spectacular
- **Modern Architecture**: Clean, maintainable codebase with proper separation of concerns
- **Developer Experience**: Comprehensive documentation and testing

Key Features
~~~~~~~~~~~~

**🔐 Multiple Authentication Types**

- JWT tokens with refresh support
- DRF token authentication
- Custom authentication support
- Seamless switching between authentication types

**🍪 Cookie-Based Security**

- HTTP-only cookies
- Automatic token management

**📧 Complete User Management**

- User registration with email verification
- Password reset and change
- Email verification workflows
- User profile management

**🔒 Multi-Factor Authentication (MFA)**

- Email-based MFA support
- Backup codes for account recovery
- Extensible MFA handler system
- Inspired by django-trench but simplified

**🌐 Enhanced Social Authentication**

- Django Allauth integration
- Automatic URL pattern generation
- Social account management views
- Support for 50+ providers

**🌍 Internationalization**

- Built-in support for 57 languages
- Major languages include: English, Spanish, French, German, Chinese, Japanese, Korean, Vietnamese, Russian, Arabic, Portuguese, Italian, Dutch, and more
- Translation support for all authentication messages and MFA responses

**🚀 Superior Developer Experience**

- **Full type hints** with mypy and pyright
- **Complete DRF Spectacular integration** for OpenAPI schema generation
- **Even custom authentication** generates proper API documentation
- **Comprehensive test coverage** (>95%)
- **Auto-generated API documentation** with interactive UI
- **Easy customization** from views to serializers

Architecture Overview
~~~~~~~~~~~~~~~~~~~~~

DRF Auth Kit follows a modular architecture that allows for easy customization and extension:

**Core Components:**

1. **Authentication System**: Pluggable authentication backends (JWT, Token, Custom)
2. **Settings System**: Dynamic configuration with lazy imports
3. **URL System**: Conditional URL patterns based on configuration
4. **Serializer System**: Customizable serializers for all authentication flows
5. **View System**: Override any view without breaking functionality

**Optional Components:**

1. **MFA System**: Pluggable multi-factor authentication handlers
2. **Social System**: Integration with Django Allauth for social authentication
3. **Cookie System**: HTTP-only cookie management with security features

**Design Principles:**

- **Override, Don't Replace**: Extend existing components rather than replacing them
- **Type Safety**: Complete type hints throughout the codebase
- **Documentation**: Automatic OpenAPI schema generation
- **Testing**: Comprehensive test coverage with multiple test environments
- **Security**: Security best practices built-in

Getting Started
~~~~~~~~~~~~~~~

Ready to get started? Head over to the :doc:`getting-started` guide for installation and setup instructions.

**Quick Links:**

- :doc:`getting-started` - Installation and basic configuration
- :doc:`user-guides/basic-usage` - Learn the core authentication features
- :doc:`user-guides/social-authentication` - Set up social login
- :doc:`user-guides/mfa` - Enable multi-factor authentication
- :doc:`user-guides/customization` - Customize the authentication flow

Community and Support
~~~~~~~~~~~~~~~~~~~~~

**Contributing**

We welcome contributions! See our :doc:`contributing` guide for details on how to contribute to DRF Auth Kit.

**Issues and Support**

- Report bugs or request features on `GitHub Issues <https://github.com/forthecraft/drf-auth-kit/issues>`_
- Check the documentation for common solutions
- Review the test cases for usage examples

**Changelog**

See the :doc:`changelog` for information about recent changes and updates.
