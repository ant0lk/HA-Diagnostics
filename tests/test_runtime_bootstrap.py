"""Descriptor-contract tests; mocked Linux ownership is not container evidence."""
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from ha_diagnostics import runtime


@pytest.fixture
def linux_fds(monkeypatch):
    """Use real regular-file FDs, emulate Linux dir_fd/ownership on Windows."""
    originals={name:getattr(os,name,None) for name in
               ("open","close","fstat","stat","lstat","mkdir","fsync")}
    directory_flag=0x10000000;nofollow_flag=0x20000000;nonblock_flag=0x40000000
    monkeypatch.setattr(runtime.os,"O_DIRECTORY",directory_flag,raising=False)
    monkeypatch.setattr(runtime.os,"O_NOFOLLOW",nofollow_flag,raising=False)
    monkeypatch.setattr(runtime.os,"O_NONBLOCK",nonblock_flag,raising=False)
    paths={};virtual=set();metadata={};changes=[];opened=[];links=set();next_fd=[100000]
    def target(name,parent=None):
        return paths[parent]/name if parent is not None else Path(name)
    def open_fd(name,flags,mode=0o777,*,dir_fd=None):
        path=target(name,dir_fd)
        try:info=originals["lstat"](path)
        except FileNotFoundError:info=None
        if flags&nofollow_flag and (path in links or info is not None and stat.S_ISLNK(info.st_mode)):
            raise OSError("nofollow")
        if flags&directory_flag:
            if info is None:raise FileNotFoundError()
            if not stat.S_ISDIR(info.st_mode):raise NotADirectoryError()
            fd=next_fd[0];next_fd[0]+=1;virtual.add(fd)
        else:
            fd=originals["open"](path,flags&~(directory_flag|nofollow_flag|nonblock_flag),mode)
        paths[fd]=path;opened.append((path,flags,dir_fd));return fd
    def fstat(fd):
        real=originals["lstat"](paths[fd]) if fd in virtual else originals["fstat"](fd)
        uid,gid,mode=metadata.get(paths[fd],(0,0,0o755 if fd in virtual else 0o600))
        return SimpleNamespace(st_mode=stat.S_IFMT(real.st_mode)|mode,st_uid=uid,st_gid=gid,
                               st_nlink=real.st_nlink,st_size=real.st_size)
    def fchown(fd,uid,gid):
        info=fstat(fd);metadata[paths[fd]]=(uid,gid,stat.S_IMODE(info.st_mode))
        changes.append(("owner",paths[fd],uid,gid,fd))
    def fchmod(fd,mode):
        info=fstat(fd);metadata[paths[fd]]=(info.st_uid,info.st_gid,mode)
        changes.append(("mode",paths[fd],mode,fd))
    def close(fd):
        if fd not in virtual:originals["close"](fd)
        paths.pop(fd,None);virtual.discard(fd)
    def mkdir(name,mode=0o777,*,dir_fd=None):
        originals["mkdir"](target(name,dir_fd),mode)
    def fsync(fd):
        if fd not in virtual:originals["fsync"](fd)
    monkeypatch.setattr(runtime.os,"open",open_fd)
    monkeypatch.setattr(runtime.os,"fstat",fstat)
    monkeypatch.setattr(runtime.os,"fchown",fchown,raising=False)
    monkeypatch.setattr(runtime.os,"fchmod",fchmod,raising=False)
    monkeypatch.setattr(runtime.os,"close",close)
    monkeypatch.setattr(runtime.os,"mkdir",mkdir)
    monkeypatch.setattr(runtime.os,"fsync",fsync)
    monkeypatch.setattr(runtime.os,"chown",lambda *a,**k:pytest.fail("path chown forbidden"),raising=False)
    return SimpleNamespace(paths=paths,metadata=metadata,changes=changes,opened=opened,links=links,
                           nofollow=nofollow_flag,directory=directory_flag)


def test_bootstrap_prepares_all_roles_and_policy_through_pinned_fds(tmp_path,linux_fds):
    (tmp_path/"transport").mkdir()
    (tmp_path/"transport/relay.json").write_text('{"origin":"https://relay.example.test"}')
    (tmp_path/"transport/relay-device-key").write_text("SYNTHETIC_RELAY_KEY")
    assert runtime.prepare_bootstrap_storage(tmp_path,"import_only")=={"relay":True}
    assert json.loads((tmp_path/"public/policy.json").read_text())["mode"]=="import_only"
    for name,(uid,gid,mode) in runtime.BootstrapStorage.DIRECTORIES.items():
        assert linux_fds.metadata[tmp_path/name]==(uid,gid,mode)
    assert linux_fds.metadata[tmp_path/"transport/relay-device-key"]==(10004,10004,0o600)
    assert linux_fds.metadata[tmp_path/"public/policy.json"]==(10001,11000,0o640)
    assert all(flags&linux_fds.nofollow for _,flags,_ in linux_fds.opened)
    assert not linux_fds.paths


@pytest.mark.parametrize("name",["query","transport","public","private","ipc"])
def test_bootstrap_worker_directory_symlink_never_changes_external_inode(tmp_path,linux_fds,name):
    external=tmp_path/"image-code";external.mkdir()
    (tmp_path/name).mkdir()
    linux_fds.links.add(tmp_path/name) # emulate Linux ELOOP without Windows privilege
    with pytest.raises(RuntimeError,match="UNSAFE_BOOTSTRAP_STORAGE"):
        runtime.prepare_bootstrap_storage(tmp_path,"live")
    assert all(change[1]!=external for change in linux_fds.changes)
    assert not linux_fds.paths


@pytest.mark.parametrize("directory,name,config",[
    ("query","introspection.secret",None),
    ("transport","control-plane-api-key",'{"tunnel_id":"tunnel_abcdefgh"}'),
    ("transport","tunnel.json",'{"tunnel_id":"tunnel_abcdefgh"}'),
    ("transport","relay.json",'{"origin":"https://relay.example.test"}'),
    ("transport","relay-device-key",'{"origin":"https://relay.example.test"}'),
    ("public","policy.json",None),
])
def test_bootstrap_leaf_symlinks_are_denied_before_metadata_change(tmp_path,linux_fds,directory,name,config):
    (tmp_path/directory).mkdir()
    external=tmp_path/"image-code.py";external.write_text("IMMUTABLE_IMAGE_CANARY")
    leaf=tmp_path/directory/name;leaf.write_text("LINK_PLACEHOLDER")
    linux_fds.links.add(leaf)
    if config:
        (tmp_path/directory/("tunnel.json" if "tunnel_id" in config else "relay.json")).write_text(config)
    with pytest.raises(RuntimeError,match="UNSAFE_BOOTSTRAP_STORAGE"):
        runtime.prepare_bootstrap_storage(tmp_path,"live")
    assert all(change[1] not in {external,leaf} for change in linux_fds.changes)
    assert external.read_text()=="IMMUTABLE_IMAGE_CANARY"
    assert not linux_fds.paths


def test_bootstrap_data_and_options_symlink_contract(tmp_path,linux_fds):
    linux_fds.links.add(tmp_path)
    with pytest.raises(RuntimeError,match="UNSAFE_BOOTSTRAP_STORAGE"):
        runtime.read_bootstrap_options(tmp_path)
    linux_fds.links.clear()
    options=tmp_path/"options.json";options.write_text("{}")
    linux_fds.links.add(options)
    with pytest.raises(RuntimeError,match="UNSAFE_BOOTSTRAP_STORAGE"):
        runtime.read_bootstrap_options(tmp_path)
    assert not linux_fds.changes
    assert not linux_fds.paths


@pytest.mark.parametrize("directory,name,config",[
    ("query","introspection.secret",None),
    ("transport","control-plane-api-key",'{"tunnel_id":"tunnel_abcdefgh"}'),
    ("transport","relay-device-key",'{"origin":"https://relay.example.test"}'),
    ("public","policy.json",None),
])
def test_bootstrap_hardlinked_leaf_is_rejected_before_metadata_change(tmp_path,linux_fds,directory,name,config):
    (tmp_path/directory).mkdir()
    external=tmp_path/"image-code.py";external.write_text("IMMUTABLE_IMAGE_CANARY")
    try:os.link(external,tmp_path/directory/name)
    except OSError:pytest.skip("Filesystem does not permit hardlinks")
    if config:
        (tmp_path/directory/("tunnel.json" if "tunnel_id" in config else "relay.json")).write_text(config)
    with pytest.raises(RuntimeError,match="UNSAFE_BOOTSTRAP_STORAGE"):
        runtime.prepare_bootstrap_storage(tmp_path,"live")
    assert external.read_text()=="IMMUTABLE_IMAGE_CANARY"
    assert all(change[1] not in {external,tmp_path/directory/name} for change in linux_fds.changes)
    assert not linux_fds.paths


def test_bootstrap_rejects_untrusted_data_owner_and_writable_data(tmp_path,linux_fds):
    for metadata in [(10004,10004,0o700),(0,0,0o777)]:
        linux_fds.metadata[tmp_path]=metadata
        with pytest.raises(RuntimeError,match="UNSAFE_BOOTSTRAP_STORAGE"):
            runtime.prepare_bootstrap_storage(tmp_path,"live")
        assert not linux_fds.changes
        assert not linux_fds.paths


def test_bootstrap_options_are_bounded_root_owned_single_link_and_strict(tmp_path,linux_fds):
    options=tmp_path/"options.json"
    options.write_text('{"mode":"live","ingress_admin_id":"owner"}')
    assert runtime.read_bootstrap_options(tmp_path)=={"mode":"live","ingress_admin_id":"owner"}
    assert linux_fds.metadata[options]==(0,0,0o600)
    options.write_text('{"url":"http://supervisor/core/restart"}')
    with pytest.raises(RuntimeError,match="INVALID_BOOTSTRAP_OPTIONS"):
        runtime.read_bootstrap_options(tmp_path)
    options.write_bytes(b"x"*16385)
    with pytest.raises(RuntimeError,match="BOOTSTRAP_SETTINGS_LIMIT"):
        runtime.read_bootstrap_options(tmp_path)
    options.write_text("{}")
    linux_fds.metadata[options]=(10004,10004,0o600)
    with pytest.raises(RuntimeError,match="UNSAFE_BOOTSTRAP_STORAGE"):
        runtime.read_bootstrap_options(tmp_path)
    assert not linux_fds.paths


def test_bootstrap_options_hardlink_is_denied(tmp_path,linux_fds):
    external=tmp_path/"image-code.py";external.write_text("{}")
    try:os.link(external,tmp_path/"options.json")
    except OSError:pytest.skip("Filesystem does not permit hardlinks")
    with pytest.raises(RuntimeError,match="UNSAFE_BOOTSTRAP_STORAGE"):
        runtime.read_bootstrap_options(tmp_path)
    assert not linux_fds.changes
    assert not linux_fds.paths


def test_bootstrap_metadata_mutation_keeps_opened_inode_when_entry_replaced(tmp_path,linux_fds,monkeypatch):
    (tmp_path/"query").mkdir()
    secret=tmp_path/"query/introspection.secret";secret.write_text("SYNTHETIC_IDP_KEY")
    displaced=tmp_path/"query/displaced.secret";displaced.write_text("SYNTHETIC_IDP_KEY")
    original_open=runtime.os.open
    def pinned_inode(name,flags,mode=0o777,*,dir_fd=None):
        if name=="introspection.secret":
            fd=original_open(displaced,flags,mode)
            linux_fds.paths[fd]=secret
            return fd
        return original_open(name,flags,mode,dir_fd=dir_fd)
    monkeypatch.setattr(runtime.os,"open",pinned_inode)
    original_fchown=runtime.os.fchown
    def replace_before_chown(fd,uid,gid):
        if linux_fds.paths[fd]==secret:
            # Windows cannot rename an open CRT descriptor. Model the replaced
            # entry while retaining a real FD pinned to the original inode.
            secret.write_text("ATTACKER_REPLACEMENT")
            # The real FD remains the displaced original inode. No path call is
            # permitted to mutate the newly substituted directory entry.
            assert os.read(fd,1)==b""  # bounded read already reached EOF
            linux_fds.paths[fd]=displaced
        original_fchown(fd,uid,gid)
    monkeypatch.setattr(runtime.os,"fchown",replace_before_chown)
    assert runtime.prepare_bootstrap_storage(tmp_path,"import_only")=={}
    assert displaced.read_text()=="SYNTHETIC_IDP_KEY"
    assert secret not in linux_fds.metadata
    assert linux_fds.metadata[displaced]==(10002,10002,0o600)
    assert not linux_fds.paths
