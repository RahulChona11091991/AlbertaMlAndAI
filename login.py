"""Basic login logic for an application.

This module provides a simple user authentication mechanism. It stores
usernames with hashed passwords and exposes the ``verify_login`` function
for credential validation.
"""

import hashlib

# Example in-memory user database.
_USERS = {
    "alice": "password123",
    "bob": "securepass",
}

def _hash_password(password: str) -> str:
    """Return a SHA-256 hash for the provided password."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

# Pre-compute hashed passwords for the stored users.
_STORED_HASHES = {user: _hash_password(pw) for user, pw in _USERS.items()}

def verify_login(username: str, password: str) -> bool:
    """Validate a username/password pair.

    Args:
        username: The user's login name.
        password: The plain-text password.

    Returns:
        ``True`` if the credentials match; otherwise ``False``.
    """
    stored_hash = _STORED_HASHES.get(username)
    if stored_hash is None:
        return False
    return stored_hash == _hash_password(password)
