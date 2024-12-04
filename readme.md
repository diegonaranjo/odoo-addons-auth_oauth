This repository contains fixes for the Odoo auth_oauth module, specifically designed to resolve common issues with Google OAuth2 authentication.
Key Improvements:

HTTPS enforcement for redirect URLs
Improved handling of existing users during login process
Detailed logging for better diagnostics
Fix for "redirect_uri_mismatch" error with Google OAuth2

Issues Resolved:

HTTP URLs being sent to Google OAuth2
Authentication failure when user already exists in database
Google's redirect_uri_mismatch error
Handling of existing users with same email
