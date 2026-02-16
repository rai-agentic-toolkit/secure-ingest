"""Tests for schema validation."""

import pytest
from secure_ingest.schema import Schema, Field, SchemaError
from secure_ingest import parse, ContentType


class TestField:
    def test_field_defaults(self):
        f = Field()
        assert f.type_ is None
        assert f.required is False
        assert f.nullable is False
        assert f.choices is None
        assert f.nested is None
        assert f.items is None

    def test_field_frozen(self):
        f = Field(str, required=True)
        with pytest.raises(AttributeError):
            f.required = False


class TestSchemaBasic:
    def test_valid_data(self):
        schema = Schema({"name": Field(str), "age": Field(int)})
        warnings = schema.validate({"name": "Alice", "age": 30})
        assert warnings == []

    def test_missing_required(self):
        schema = Schema({"name": Field(str, required=True)})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({})
        assert "missing_required:name" in exc_info.value.violations

    def test_multiple_missing_required(self):
        schema = Schema({
            "name": Field(str, required=True),
            "email": Field(str, required=True),
        })
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({})
        assert len(exc_info.value.violations) == 2

    def test_unexpected_field_denied(self):
        schema = Schema({"name": Field(str)})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({"name": "Alice", "hacker": "payload"})
        assert "unexpected_field:hacker" in exc_info.value.violations

    def test_extra_fields_allowed(self):
        schema = Schema({"name": Field(str)}, allow_extra=True)
        warnings = schema.validate({"name": "Alice", "extra": "ok"})
        assert warnings == []

    def test_non_dict_rejected(self):
        schema = Schema({"name": Field(str)})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate("not a dict")
        assert "type_error:root" in exc_info.value.violations

    def test_non_dict_list_rejected(self):
        schema = Schema({"name": Field(str)})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate([1, 2, 3])
        assert "type_error:root" in exc_info.value.violations


class TestTypeChecking:
    def test_wrong_type(self):
        schema = Schema({"age": Field(int)})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({"age": "thirty"})
        assert any("type_error:age" in v for v in exc_info.value.violations)

    def test_bool_not_int_strict(self):
        schema = Schema({"count": Field(int)})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({"count": True})
        assert any("expected_int_got_bool" in v for v in exc_info.value.violations)

    def test_bool_is_bool(self):
        schema = Schema({"flag": Field(bool)})
        warnings = schema.validate({"flag": True})
        assert warnings == []

    def test_none_type_accepts_anything(self):
        schema = Schema({"data": Field()})
        schema.validate({"data": "string"})
        schema.validate({"data": 42})
        schema.validate({"data": [1, 2]})

    def test_nullable_field(self):
        schema = Schema({"name": Field(str, nullable=True)})
        warnings = schema.validate({"name": None})
        assert warnings == []

    def test_null_not_allowed(self):
        schema = Schema({"name": Field(str)})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({"name": None})
        assert "null_not_allowed:name" in exc_info.value.violations


class TestChoices:
    def test_valid_choice(self):
        schema = Schema({"status": Field(str, choices=("active", "inactive"))})
        schema.validate({"status": "active"})

    def test_invalid_choice(self):
        schema = Schema({"status": Field(str, choices=("active", "inactive"))})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({"status": "deleted"})
        assert any("invalid_choice:status" in v for v in exc_info.value.violations)


class TestNestedSchema:
    def test_valid_nested(self):
        address_schema = Schema({
            "street": Field(str, required=True),
            "city": Field(str, required=True),
        })
        schema = Schema({
            "name": Field(str),
            "address": Field(dict, nested=address_schema),
        })
        schema.validate({
            "name": "Alice",
            "address": {"street": "123 Main", "city": "Springfield"},
        })

    def test_invalid_nested(self):
        address_schema = Schema({
            "street": Field(str, required=True),
        })
        schema = Schema({
            "address": Field(dict, nested=address_schema),
        })
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({"address": {}})
        assert "address.missing_required:street" in exc_info.value.violations

    def test_nested_unexpected_field(self):
        inner = Schema({"x": Field(int)})
        schema = Schema({"data": Field(dict, nested=inner)})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({"data": {"x": 1, "y": 2}})
        assert "data.unexpected_field:y" in exc_info.value.violations


class TestListItems:
    def test_list_of_typed_items(self):
        schema = Schema({
            "tags": Field(list, items=Field(str)),
        })
        schema.validate({"tags": ["a", "b", "c"]})

    def test_list_item_wrong_type(self):
        schema = Schema({
            "tags": Field(list, items=Field(str)),
        })
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({"tags": ["a", 42, "c"]})
        assert any("tags[1]" in v for v in exc_info.value.violations)

    def test_list_of_objects(self):
        item_schema = Schema({
            "id": Field(int, required=True),
            "name": Field(str),
        })
        schema = Schema({
            "items": Field(list, items=item_schema),
        })
        schema.validate({"items": [
            {"id": 1, "name": "one"},
            {"id": 2, "name": "two"},
        ]})

    def test_list_of_objects_violation(self):
        item_schema = Schema({"id": Field(int, required=True)})
        schema = Schema({"items": Field(list, items=item_schema)})
        with pytest.raises(SchemaError) as exc_info:
            schema.validate({"items": [{"id": 1}, {}]})
        assert "items[1].missing_required:id" in exc_info.value.violations


class TestParseIntegration:
    def test_json_with_schema(self):
        schema = Schema({"name": Field(str, required=True)})
        result = parse('{"name": "Alice"}', ContentType.JSON, schema=schema)
        assert result.content == {"name": "Alice"}

    def test_json_schema_failure(self):
        schema = Schema({"name": Field(str, required=True)})
        with pytest.raises(SchemaError):
            parse('{"age": 30}', ContentType.JSON, schema=schema)

    def test_json_schema_rejects_extra(self):
        schema = Schema({"name": Field(str)})
        with pytest.raises(SchemaError) as exc_info:
            parse('{"name": "Alice", "evil": "payload"}', ContentType.JSON, schema=schema)
        assert "unexpected_field:evil" in exc_info.value.violations

    def test_yaml_with_schema(self):
        schema = Schema({"host": Field(str, required=True), "port": Field(int)})
        result = parse("host: localhost\nport: 8080", ContentType.YAML, schema=schema)
        assert result.content["host"] == "localhost"

    def test_text_schema_ignored(self):
        """Schema doesn't apply to text (not a dict)."""
        schema = Schema({"name": Field(str)})
        # Should NOT raise — text content is a string, not a dict
        result = parse("hello world", ContentType.TEXT, schema=schema)
        assert result.content == "hello world"

    def test_xml_with_schema(self):
        schema = Schema({
            "item": Field(dict),
        }, allow_extra=True)
        result = parse("<root><item>data</item></root>", ContentType.XML, schema=schema)
        assert "root" in result.content


class TestSchemaProperties:
    def test_fields_property(self):
        schema = Schema({"a": Field(str), "b": Field(int)})
        fields = schema.fields
        assert set(fields.keys()) == {"a", "b"}

    def test_allow_extra_property(self):
        schema = Schema({}, allow_extra=True)
        assert schema.allow_extra is True

    def test_empty_schema_rejects_any_field(self):
        schema = Schema({})
        with pytest.raises(SchemaError):
            schema.validate({"anything": "fails"})

    def test_empty_schema_empty_dict(self):
        schema = Schema({})
        schema.validate({})
