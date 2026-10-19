import os

import pytest

from scan_policy import is_path_inside, is_url_allowed, resolve_scans, split_setting


def test_repo_inside_allowed_root_is_allowed(tmp_path):
    repo = tmp_path / "NodeGoat"
    repo.mkdir()
    assert is_path_inside(str(repo), [str(tmp_path)])


def test_repo_outside_allowed_root_is_refused(tmp_path):
    outside = os.path.dirname(str(tmp_path))
    assert not is_path_inside(outside, [str(tmp_path)])


def test_dot_dot_cannot_escape_allowed_root(tmp_path):
    escape = os.path.join(str(tmp_path), "NodeGoat", "..", "..")
    assert not is_path_inside(escape, [str(tmp_path)])


def test_sibling_folder_with_same_prefix_is_refused(tmp_path):
    allowed = tmp_path / "Targets"
    evil = tmp_path / "TargetsEvil"
    allowed.mkdir()
    evil.mkdir()
    assert not is_path_inside(str(evil), [str(allowed)])


def test_nothing_allowed_when_not_configured(tmp_path):
    assert not is_path_inside(str(tmp_path), [])
    assert not is_url_allowed("http://localhost:4000", [])


@pytest.mark.parametrize("url, expected", [
    ("http://host.docker.internal:4000", True),
    ("https://LOCALHOST/login", True),
    ("http://192.168.1.1", False),
    ("http://host.docker.internal.evil.com", False),
    ("ftp://localhost", False),
    ("file:///C:/Windows/win.ini", False),
])
def test_only_allowed_hosts_can_be_scanned(url, expected):
    assert is_url_allowed(url, ["host.docker.internal", "localhost"]) is expected


def test_scans_are_inferred_from_inputs():
    assert resolve_scans(None, repo_path="C:/repo") == ["sast", "dependency"]
    assert resolve_scans(None, image="nodegoat:latest", target_url="http://localhost") == ["container", "dast"]


@pytest.mark.parametrize("scans, kwargs", [
    (None, {}),
    (["sast"], {}),
    (["container"], {"repo_path": "C:/repo"}),
    (["dast"], {"image": "nodegoat"}),
])
def test_missing_inputs_are_rejected(scans, kwargs):
    with pytest.raises(ValueError):
        resolve_scans(scans, **kwargs)


def test_split_setting_ignores_blanks():
    assert split_setting(" a ; ;b ", ";") == ["a", "b"]
    assert split_setting(None, ",") == []