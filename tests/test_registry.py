from dataclasses import replace
import importlib
import pytest
from watchtower.registry import REGISTRY, SourceDefinition, SourceRegistry


def test_registry_validates_metadata():
    definition = REGISTRY.get('dns')
    with pytest.raises(ValueError, match='duplicate'):
        SourceRegistry((definition, definition))
    with pytest.raises(ValueError, match='capabilities'):
        replace(definition, capabilities=('made_up',))
    with pytest.raises(ValueError, match='adapter'):
        replace(definition, adapter='')
    assert REGISTRY.get('reddit').missing_credentials({'REDDIT_CLIENT_ID': 'present'}) == ['REDDIT_CLIENT_SECRET']
    assert REGISTRY.get('urlhaus').public({})['status'] == 'auth_missing'
    assert REGISTRY.get('dns').public({'ENABLE_DNS': 'false'})['status'] == 'disabled'
    assert 'dns' in {s.id for s in REGISTRY.for_capability('dns_lookup')}


def test_every_catalog_adapter_resolves():
    for definition in REGISTRY.all():
        module, name = definition.adapter.split(':')
        assert callable(getattr(importlib.import_module(module), name))


def test_metadata_has_no_secret_values():
    assert 'private-test-value' not in str(REGISTRY.get('urlhaus').public({'ABUSECH_AUTH_KEY': 'private-test-value'}))
