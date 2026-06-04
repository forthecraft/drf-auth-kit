Upcoming Features
=================

This document outlines planned features and enhancements for DRF Auth Kit. These features will be implemented while maintaining backward compatibility.

Enhanced Multi-Factor Authentication
------------------------------------

**SMS & Voice Integration**

- ☐ **Twilio Integration**: Built-in SMS and voice-based MFA delivery via Twilio
- ☐ **International Support**: Global SMS delivery with country-specific optimizations
- ☐ **Voice Calls**: Audio verification codes for accessibility and backup methods

**Trusted Device Management**

- ☐ **Device Fingerprinting**: Secure device identification and tracking
- ☐ **Trusted Sessions**: Remember MFA verification for trusted browsers/sessions
- ☐ **Configurable Duration**: Flexible trust periods (hours, days, weeks)

Passwordless Authentication
---------------------------

**SMS-Based Login**

- ☐ **One-Time Passwords**: SMS-delivered codes for passwordless authentication
- ☐ **Phone Number Verification**: Secure phone number validation and management

Advanced Security Features
--------------------------

**Rate Limiting & Protection**

- ☐ **Configurable Limits**: Customizable rate limits for all authentication endpoints
- ☐ **Progressive Delays**: Increasing delays for repeated failed attempts
- ☐ **Account Lockout**: Temporary and permanent account lockout mechanisms
- ☐ **IP-Based Restrictions**: Geographic and IP-based access controls

**Security Enhancements**

- ☐ **Enhanced CSRF Protection**: Improved CSRF protection and security headers
- ☐ **Breach Detection**: Integration with breach detection services

Contributing to Development
---------------------------

We welcome contributions to help implement these features:

**How to Get Involved**

- **GitHub Issues**: Track feature development and report bugs
- **Pull Requests**: Submit code contributions following our guidelines
- **Discussions**: Join community discussions about feature priorities
- **Feature Requests**: Submit detailed feature requests with use cases

**Development Guidelines**

- All new features must maintain backward compatibility
- Comprehensive tests required for all new functionality
- Follow existing code style and architectural patterns
- Update documentation for any new features

For more information about contributing, see our :doc:`contributing` guide.
