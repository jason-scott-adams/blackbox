"""Custom exceptions for Black Box.

All exceptions inherit from BlackBoxError with context fields
for better error tracking and debugging.
"""

from typing import Any


class BlackBoxError(Exception):
    """Base exception for all Black Box errors.

    Includes context dict for structured error information.
    """

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def __str__(self) -> str:
        if self.context:
            ctx_str = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{self.message} ({ctx_str})"
        return self.message


class DataValidationError(BlackBoxError):
    """Raised when data fails validation."""

    pass


class DetectorError(BlackBoxError):
    """Raised when a detector encounters an error."""

    pass


class ClientError(BlackBoxError):
    """Raised when an external client operation fails."""

    pass


class ConfigurationError(BlackBoxError):
    """Raised when configuration is invalid or missing."""

    pass


class EntityNotFoundError(BlackBoxError):
    """Raised when an entity cannot be found."""

    pass


class AlertNotFoundError(BlackBoxError):
    """Raised when an alert cannot be found."""

    pass
