import json
from pathlib import Path

import pytest

from ha_diagnostics.local_setup import SetupError, main, provision


def test_fixed_local_files_and_secret_not_in_metadata(tmp_path, capsys):
    provision(tmp_path, tunnel_id="tunnel_fixture12345", tunnel_key="SYNTHETIC_TUNNEL_KEY", introspection_secret="SYNTHETIC_IDP_SECRET")
    assert (tmp_path / "transport/control-plane-api-key").read_text() == "SYNTHETIC_TUNNEL_KEY"
    assert json.loads((tmp_path / "transport/tunnel.json").read_text()) == {"tunnel_id": "tunnel_fixture12345"}
    assert (tmp_path / "query/introspection.secret").read_text() == "SYNTHETIC_IDP_SECRET"
    assert capsys.readouterr().out == ""
    assert "SYNTHETIC_TUNNEL_KEY" not in (tmp_path / "transport/tunnel.json").read_text()


@pytest.mark.parametrize("values", [
    {"tunnel_id": "../fixture", "tunnel_key": "synthetic-secret"},
    {"tunnel_id": "tunnel_fixture12345"}, {"tunnel_key": "synthetic-secret"},
    {"introspection_secret": "secret\nINJECTED"}, {"introspection_secret": "x" * 8193},
])
def test_invalid_values_never_create_secret_files(tmp_path, values, capsys):
    with pytest.raises(SetupError):
        provision(tmp_path, **values)
    assert list(tmp_path.iterdir()) == []
    assert capsys.readouterr().out == ""


def test_secret_is_prompted_not_argument_or_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _: "tunnel_fixture12345")
    answers = iter(["SYNTHETIC_TUNNEL_KEY", "SYNTHETIC_IDP_SECRET"])
    monkeypatch.setattr("getpass.getpass", lambda _: next(answers))
    assert main(["--data", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert "SYNTHETIC" not in captured.out + captured.err
    assert "LOCAL_SETTINGS_SAVED" in captured.out


def test_symlink_secret_destination_is_not_followed(tmp_path, monkeypatch):
    (tmp_path / "transport").mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    path = tmp_path / "transport/control-plane-api-key"
    # Windows may lack symlink creation privileges: mock the path classification
    # to prove refusal, rather than claiming a kernel symlink isolation test.
    import ha_diagnostics.local_setup as setup
    original = setup._unsafe_link
    monkeypatch.setattr(setup, "_unsafe_link", lambda p: Path(p) == path or original(p))
    with pytest.raises(SetupError, match="UNSAFE_STORAGE_PATH"):
        provision(tmp_path, tunnel_id="tunnel_fixture12345", tunnel_key="synthetic-secret")
    assert outside.read_text() == "untouched" and not path.exists()


def test_symlink_parent_directory_is_rejected_before_prompt(tmp_path, monkeypatch, capsys):
    import ha_diagnostics.local_setup as setup
    monkeypatch.setattr(setup, "_unsafe_link", lambda path: Path(path) == tmp_path)
    monkeypatch.setattr("getpass.getpass", lambda _: pytest.fail("must not prompt"))
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("must not prompt"))
    assert main(["--data", str(tmp_path)]) == 1
    assert "LOCAL_SETUP_FAILED" in capsys.readouterr().err


def test_echoing_getpass_fallback_is_rejected(tmp_path, monkeypatch, capsys):
    import getpass
    import warnings
    monkeypatch.setattr("builtins.input", lambda _: "tunnel_fixture12345")
    def unsafe_prompt(_):
        warnings.warn("Password input may be echoed", getpass.GetPassWarning)
        pytest.fail("echoing fallback must not continue")
    monkeypatch.setattr("getpass.getpass", unsafe_prompt)
    assert main(["--data", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "LOCAL_SETUP_FAILED" in captured.err and "Password input" not in captured.err
    assert list(tmp_path.iterdir()) == []


def test_relay_device_key_hidden_and_metadata_contains_only_origin(tmp_path, capsys):
    provision(tmp_path, relay_origin="https://relay.example.test/", relay_device_key="SYNTHETIC_RELAY_KEY")
    config=(tmp_path/"transport/relay.json").read_text()
    assert json.loads(config)=={"origin":"https://relay.example.test"}
    assert "SYNTHETIC" not in config
    assert (tmp_path/"transport/relay-device-key").read_text()=="SYNTHETIC_RELAY_KEY"
    assert not (tmp_path/"transport/tunnel.json").exists()
    assert capsys.readouterr().out==""


@pytest.mark.parametrize("values",[
    {"relay_origin":"http://relay.example.test","relay_device_key":"synthetic-key"},
    {"relay_origin":"https://relay.example.test/path","relay_device_key":"synthetic-key"},
    {"relay_origin":"https://user:password@relay.example.test","relay_device_key":"synthetic-key"},
    {"relay_origin":"https://relay.example.test\nINJECTED","relay_device_key":"synthetic-key"},
    {"relay_origin":"https://relay.example.test"}, {"relay_device_key":"synthetic-key"},
    {"relay_origin":"https://relay.example.test","relay_device_key":"synthetic-key",
     "tunnel_id":"tunnel_fixture12345","tunnel_key":"synthetic-key"},
])
def test_invalid_relay_values_create_nothing(tmp_path,values):
    with pytest.raises(SetupError):provision(tmp_path,**values)
    assert list(tmp_path.iterdir())==[]


def test_existing_tunnel_is_preserved_when_relay_conflicts(tmp_path):
    provision(tmp_path,tunnel_id="tunnel_fixture12345",tunnel_key="SYNTHETIC_TUNNEL_KEY")
    with pytest.raises(SetupError,match="TRANSPORT_CONFLICT"):
        provision(tmp_path,relay_origin="https://relay.example.test",relay_device_key="SYNTHETIC_RELAY_KEY")
    assert (tmp_path/"transport/control-plane-api-key").read_text()=="SYNTHETIC_TUNNEL_KEY"
    assert not (tmp_path/"transport/relay-device-key").exists()


def test_relay_key_prompt_is_getpass_and_not_output(tmp_path,monkeypatch,capsys):
    answers=iter(["","https://relay.example.test"])
    monkeypatch.setattr("builtins.input",lambda _:next(answers))
    secrets=iter(["SYNTHETIC_RELAY_KEY",""])
    monkeypatch.setattr("getpass.getpass",lambda _:next(secrets))
    assert main(["--data",str(tmp_path)])==0
    captured=capsys.readouterr()
    assert "SYNTHETIC" not in captured.out+captured.err
    assert (tmp_path/"transport/relay-device-key").read_text()=="SYNTHETIC_RELAY_KEY"
