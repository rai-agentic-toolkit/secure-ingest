"""Schema validation for structured content.

Lightweight, zero-dependency schema validation for JSON/YAML content.
Designed for AI agent ingestion: define the shape you expect, reject everything else.

Design principles:
- No external dependencies (no jsonschema)
- Declarative: describe the shape, not the validation logic
- Deny-by-default: extra fields are rejected unless explicitly allowed
- Composable: schemas can nest

Example:
    >>> from secure_ingest.schema import Schema, Field, SchemaError
    >>> schema = Schema({
    ...     "name": Field(str, required=True),
    ...     "age": Field(int),
    ...     "tags": Field(list),
    ... })
    >>> schema.validate({"name": "Alice", "age": 30})  # OK
    >>> schema.validate({"age": "thirty"})  # SchemaError: 'name' required, 'age' wrong type
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class SchemaError(Exception):
    """Raised when content fails schema validation."""

    def __init__(self, message: str, violations: list[str] | None = None):
        super().__init__(message)
        self.violations = violations or []


@dataclass(frozen=True)
class Field:
    """Declares an expected field in the schema.

    Args:
        type_: Expected Python type (str, int, float, bool, list, dict, or None for any).
        required: If True, field must be present.
        nullable: If True, field value can be None.
        choices: If set, value must be one of these.
        nested: If set, value must conform to this Schema (for dict fields).
        items: If set, each list item must conform to this Schema or Field.
    """
    type_: type | None = None
    required: bool = False
    nullable: bool = False
    choices: tuple | None = None
    nested: Schema | None = None
    items: Field | Schema | None = None


class Schema:
    """Declarative schema for structured content validation.

    Args:
        fields: Dict mapping field names to Field definitions.
        allow_extra: If True, fields not in the schema are allowed through.
            Default is False (deny-by-default).
        strict_types: If True, no type coercion (int 1 != float 1.0).
            Default is True.
    """

    def __init__(
        self,
        fields: dict[str, Field],
        *,
        allow_extra: bool = False,
        strict_types: bool = True,
    ) -> None:
        self._fields = fields
        self._allow_extra = allow_extra
        self._strict_types = strict_types

    @property
    def fields(self) -> dict[str, Field]:
        return dict(self._fields)

    @property
    def allow_extra(self) -> bool:
        return self._allow_extra

    def validate(self, data: Any) -> list[str]:
        """Validate data against this schema.

        Args:
            data: The parsed content to validate (typically a dict).

        Returns:
            List of warnings (empty if clean).

        Raises:
            SchemaError: If data fails validation. The .violations attribute
                lists all specific failures.
        """
        if not isinstance(data, dict):
            raise SchemaError(
                f"Expected dict, got {type(data).__name__}",
                violations=["type_error:root"],
            )

        violations: list[str] = []
        warnings: list[str] = []

        # Check required fields
        for name, f in self._fields.items():
            if f.required and name not in data:
                violations.append(f"missing_required:{name}")

        # Check each field present in data
        for key, value in data.items():
            if key not in self._fields:
                if not self._allow_extra:
                    violations.append(f"unexpected_field:{key}")
                continue

            f = self._fields[key]
            field_violations = self._validate_field(key, value, f)
            violations.extend(field_violations)

        if violations:
            raise SchemaError(
                f"Schema validation failed: {', '.join(violations)}",
                violations=violations,
            )

        return warnings

    def _validate_field(self, name: str, value: Any, f: Field) -> list[str]:
        """Validate a single field value. Returns list of violations."""
        violations: list[str] = []

        # Null check
        if value is None:
            if not f.nullable:
                violations.append(f"null_not_allowed:{name}")
            return violations

        # Type check
        if f.type_ is not None:
            if self._strict_types:
                # In strict mode, bool is not int (Python's bool subclasses int)
                if f.type_ is int and isinstance(value, bool):
                    violations.append(f"type_error:{name}:expected_int_got_bool")
                elif not isinstance(value, f.type_):
                    violations.append(
                        f"type_error:{name}:expected_{f.type_.__name__}"
                        f"_got_{type(value).__name__}"
                    )
            else:
                if not isinstance(value, f.type_):
                    violations.append(
                        f"type_error:{name}:expected_{f.type_.__name__}"
                        f"_got_{type(value).__name__}"
                    )

        # Choices check
        if f.choices is not None and value not in f.choices:
            violations.append(f"invalid_choice:{name}:{value}")

        # Nested schema check
        if f.nested is not None and isinstance(value, dict):
            try:
                f.nested.validate(value)
            except SchemaError as e:
                for v in e.violations:
                    violations.append(f"{name}.{v}")

        # List items check
        if f.items is not None and isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(f.items, Schema):
                    try:
                        f.items.validate(item)
                    except SchemaError as e:
                        for v in e.violations:
                            violations.append(f"{name}[{i}].{v}")
                elif isinstance(f.items, Field):
                    item_violations = self._validate_field(
                        f"{name}[{i}]", item, f.items
                    )
                    violations.extend(item_violations)

        return violations
