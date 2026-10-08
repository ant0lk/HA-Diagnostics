"""Local secret wiring only; not real TLS, IdP, Linux ownership or ChatGPT."""
import importlib.util
from pathlib import Path
import sys
import pytest
from ha_diagnostics.policy import LocalPolicy,OAuthConfig,PolicyStore

spec=importlib.util.spec_from_file_location('gateway_setup',Path('gateway/ha_diagnostics_gateway.py'))
gateway=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=gateway
spec.loader.exec_module(gateway)


def put_secret(path,value):
    path.write_text(value,encoding='utf-8')
    path.chmod(0o600)


def test_fixed_secret_bounds_and_names(tmp_path):
    put_secret(tmp_path/'device-channel-key','SyntheticDeviceChannelValueForFixtureOnly')
    assert gateway.read_fixed_secret(tmp_path,'device-channel-key').startswith('Synthetic')
    assert gateway.read_fixed_secret(tmp_path,'introspection.secret',required=False) is None
    with pytest.raises(ValueError):gateway.read_fixed_secret(tmp_path,'../other')
    put_secret(tmp_path/'introspection.secret','x'*8193)
    with pytest.raises(ValueError):gateway.read_fixed_secret(tmp_path,'introspection.secret')
    put_secret(tmp_path/'introspection.secret','Synthetic\nFixture')
    with pytest.raises(ValueError):gateway.read_fixed_secret(tmp_path,'introspection.secret')


def test_introspection_secret_reaches_verifier_without_environment(tmp_path,monkeypatch):
    put_secret(tmp_path/'device-channel-key','SyntheticDeviceChannelValueForFixtureOnly')
    value='SyntheticIntrospectionValueForFixtureOnly'
    put_secret(tmp_path/'introspection.secret',value)
    calls=[]
    def factory(config,*,introspection_secret):
        calls.append(introspection_secret)
        return object()
    monkeypatch.setenv('INTROSPECTION_SECRET','unrelated-fixture-environment')
    instance=gateway.create_gateway(tmp_path,verifier_factory=factory)
    instance.verify(instance.policies.read().oauth)
    assert calls==[value]


def test_secret_symlink_is_rejected(tmp_path):
    target=tmp_path/'fixture';put_secret(target,'SyntheticDeviceChannelValueForFixtureOnly')
    link=tmp_path/'device-channel-key'
    try:link.symlink_to(target)
    except OSError:pytest.skip('Windows symlink privilege unavailable; Linux acceptance still required')
    with pytest.raises(ValueError):gateway.read_fixed_secret(tmp_path,'device-channel-key')


def test_confidential_introspection_missing_secret_fails_before_calls(tmp_path):
    put_secret(tmp_path/'device-channel-key','SyntheticDeviceChannelValueForFixtureOnly')
    PolicyStore(tmp_path/'policy.json').write(LocalPolicy(oauth=OAuthConfig(introspection_uri='https://idp.example.test/introspect')))
    with pytest.raises(ValueError,match='GATEWAY_INTROSPECTION_SECRET_REQUIRED'):
        gateway.create_gateway(tmp_path)
