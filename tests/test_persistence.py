"""Accounts, credentials, locks and refresh tokens survive a restart (SQLite store); admin commands."""

import base64
import hashlib
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import admin  # noqa: E402
import csc_server  # noqa: E402
import pki  # noqa: E402
import store as store_mod  # noqa: E402
from test_enrollment import (ADV, B, basic, c, confirm_link, create, creation_token, inbox,  # noqa: E402,F401
                             register, service_token, signup)


def restart():
    """What a container restart does: in-memory state is gone, the database is reopened."""
    csc_server.STATE.store.close()
    csc_server.STATE = csc_server.build_state()


def adv_credential(c, inbox, pin="2468"):
    register(c, inbox)
    token = creation_token(c, ADV, pin=pin)["access_token"]
    r = create(c, token, ADV)
    assert r.status_code == 201, r.text
    return r.json()["credentialID"]


def sign(c, headers, cid, pin="2468"):
    digest = hashlib.sha256(b"contract").digest()
    r = c.post(f"{B}/credentials/authorize", headers=headers, json={
        "credentialID": cid, "numSignatures": 1, "authData": [{"id": "PIN", "value": pin}]})
    if r.status_code != 200:
        return r
    return c.post(f"{B}/signatures/signHash", headers=headers, json={
        "credentialID": cid, "SAD": r.json()["SAD"], "hashes": [base64.b64encode(digest).decode()],
        "hashAlgorithmOID": csc_server.OID_SHA256, "signAlgo": csc_server.OID_SHA256_RSA})


def test_account_and_credential_survive_restart(c, inbox):
    cid = adv_credential(c, inbox)
    restart()
    headers = service_token(c)  # the account is still there, password included
    listed = c.post(f"{B}/credentials/list", headers=headers, json={"credentialInfo": True, "certInfo": True}).json()
    assert listed["credentialIDs"] == [cid]
    assert "CN=Bob Builder" in listed["credentialInfos"][0]["cert"]["subjectDN"]
    r = sign(c, headers, cid)  # key loaded back from its file, PIN hash from the database
    assert r.status_code == 200 and len(r.json()["signatures"]) == 1, r.text


def test_confirmation_link_survives_restart(c, inbox):
    assert signup(c).status_code == 200
    link = confirm_link(inbox)
    restart()
    assert c.get(link).status_code == 200
    assert c.get(link).status_code == 400  # still single use
    service_token(c)


def test_lock_survives_restart_and_admin_unlocks(c, inbox, capsys):
    cid = adv_credential(c, inbox)
    headers = service_token(c)
    for _ in range(csc_server.MAX_AUTH_FAILURES):
        sign(c, headers, cid, pin="0000")
    restart()
    headers = service_token(c)
    assert "disabled" in sign(c, headers, cid).json()["error_description"]

    assert admin.main(["unlock", cid]) == 0
    assert sign(c, headers, cid).status_code == 200


def test_demo_account_follows_configuration(c, monkeypatch):
    alice = {"Authorization": "Basic " + base64.b64encode(b"alice:alice-password").decode()}
    tok = c.post(f"{B}/auth/login", json={}, headers=alice).json()["access_token"]
    for _ in range(csc_server.MAX_AUTH_FAILURES):  # lock alice's credential
        sign(c, {"Authorization": f"Bearer {tok}"}, "cred-alice-adv", pin="0000")

    monkeypatch.setenv("DEMO_USER_PASSWORD", "a-new-password")
    restart()
    assert c.post(f"{B}/auth/login", json={}, headers=alice).status_code == 400
    r = c.post(f"{B}/auth/login", json={}, headers=basic("alice", "a-new-password"))
    headers = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert sign(c, headers, "cred-alice-adv", pin="1234").status_code == 200  # demo credentials reset on start


def test_refresh_token_survives_restart_and_is_stored_hashed(c):
    r = c.post(f"{B}/auth/login", json={"rememberMe": True}, headers=basic("alice", "alice-password"))
    refresh = r.json()["refresh_token"]
    db = sqlite3.connect(csc_server.STATE.store.path)
    stored = [row[0] for row in db.execute("SELECT token_hash FROM refresh_tokens")]
    db.close()
    assert stored == [store_mod.token_hash(refresh)]

    restart()
    r = c.post(f"{B}/auth/login", json={"refresh_token": refresh})
    assert r.status_code == 200, r.text
    access = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert c.post(f"{B}/auth/revoke", headers=access, json={"token": refresh}).status_code == 204
    assert c.post(f"{B}/auth/login", json={"refresh_token": refresh}).status_code == 400


def test_unconfirmed_accounts_expire(c, inbox):
    register(c, inbox, mail="kept@example.com")
    assert signup(c, mail="late@example.com").status_code == 200
    csc_server.STATE.store.purge_expired(time.time() + csc_server.VERIFY_TTL + 1)
    assert csc_server.STATE.store.user("late@example.com") is None
    assert csc_server.STATE.store.user("kept@example.com")["verified"]


def test_schema_version_and_newer_database_refused(tmp_path):
    s = store_mod.Store(tmp_path / "x.db")
    assert s.db.execute("PRAGMA user_version").fetchone()[0] == store_mod.SCHEMA_VERSION
    s.db.execute(f"PRAGMA user_version = {store_mod.SCHEMA_VERSION + 1}")
    s.close()
    with pytest.raises(RuntimeError, match="newer than this code"):
        store_mod.Store(tmp_path / "x.db")


def test_admin_backup_restore_and_delete(c, inbox, tmp_path, capsys):
    cid = adv_credential(c, inbox)
    archive = admin.backup(csc_server.STATE.store, tmp_path / "backups")
    assert oct(archive.stat().st_mode)[-3:] == "600"

    assert admin.main(["delete-user", "bob@example.com"]) == 0
    assert csc_server.STATE.store.user("bob@example.com") is None
    assert not (pki.DATA_DIR / f"{cid}.key.pem").exists()

    csc_server.STATE.store.close()  # restore runs with the server stopped
    assert admin.main(["restore", str(archive)]) == 0
    csc_server.STATE = csc_server.build_state()
    headers = service_token(c)
    assert sign(c, headers, cid).status_code == 200

    assert admin.main(["users"]) == 0
    out = capsys.readouterr().out
    assert "bob@example.com" in out and "alice" in out


def test_default_backups_keep_the_newest(c, tmp_path):
    folder = tmp_path / "rotating"
    folder.mkdir()
    for day in range(1, 13):  # twelve older backups
        (folder / f"csc-data-202601{day:02d}-120000.tgz").write_bytes(b"old")
    newest = admin.backup(csc_server.STATE.store, folder, keep=admin.KEEP_BACKUPS)
    kept = sorted(p.name for p in folder.glob("csc-data-*.tgz"))
    assert len(kept) == admin.KEEP_BACKUPS and newest.name == kept[-1]
    assert kept[0] == "csc-data-20260104-120000.tgz"  # the three oldest were removed
