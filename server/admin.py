"""Operator commands for the CSC demo server's data ($CSC_DATA_DIR: database + key files).

    python server/admin.py users                   accounts, their credentials, locked ones
    python server/admin.py unlock CREDENTIAL_ID    re-enable a credential locked by wrong PINs/codes
    python server/admin.py delete-user EMAIL       delete an account, its credentials and key files
    python server/admin.py backup [DIR]            consistent snapshot of database + keys, as a .tgz
                                                   (default DIR: $CSC_DATA_DIR/backups, which keeps the
                                                   newest 10); safe while the server runs
    python server/admin.py restore FILE.tgz        replace the data with a backup; STOP THE SERVER FIRST

In Docker:  docker compose exec csc-server python server/admin.py users
"""

from __future__ import annotations

import os
import sys
import tarfile
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pki  # noqa: E402
from store import Store  # noqa: E402


def db_path() -> Path:  # same rule as csc_server.db_path()
    return Path(os.environ.get("CSC_DB_PATH") or pki.DATA_DIR / "csc.db")


def users(store: Store) -> None:
    rows = store.users_overview()
    print(f"{'account':<34} {'name':<28} {'confirmed':<10} {'created':<17} creds  locked")
    for r in rows:
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["created_at"]))
        print(f"{r['username']:<34} {(r['given_name'] + ' ' + r['family_name'])[:27]:<28} "
              f"{'yes' if r['verified'] else 'no':<10} {created:<17} {r['credentials']:>5}  {r['locked']:>6}")
    print(f"{len(rows)} account(s)")


def unlock(store: Store, credential_id: str) -> int:
    if not store.unlock(credential_id):
        print(f"No credential {credential_id}")
        return 1
    print(f"Unlocked {credential_id}")
    return 0


def delete_user(store: Store, email: str) -> int:
    username = email.strip().lower()
    if username == "alice":
        print("alice is the built-in demo account; it's recreated on every start")
        return 1
    creds = [row["id"] for row in store.credentials_of(username)]
    if not store.delete_user(username):
        print(f"No account {username}")
        return 1
    for cid in creds:
        for path in (pki.DATA_DIR / f"{cid}.key.pem", pki.DATA_DIR / f"{cid}.pem"):
            path.unlink(missing_ok=True)
    print(f"Deleted {username} and {len(creds)} credential(s)")
    return 0


KEEP_BACKUPS = 10


def backup(store: Store, out_dir: Path, keep: int | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"csc-data-{time.strftime('%Y%m%d-%H%M%S')}.tgz"
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "csc.db"
        store.backup_to(snapshot)  # consistent copy, even while the server writes
        with tarfile.open(target, "w:gz") as tar:
            tar.add(snapshot, arcname="csc.db")
            for pem in sorted(pki.DATA_DIR.glob("*.pem")):
                tar.add(pem, arcname=pem.name)
    target.chmod(0o600)  # it contains private keys
    print(f"Backup written to {target}")
    if keep:
        for old in sorted(out_dir.glob("csc-data-*.tgz"), reverse=True)[keep:]:
            old.unlink()
    return target


def restore(archive: Path) -> int:
    data, db = pki.DATA_DIR, db_path()
    with tarfile.open(archive, "r:gz") as tar:
        names = tar.getnames()
        if "csc.db" not in names or any("/" in n or n.startswith(".") for n in names):
            print(f"{archive} is not a backup made by this tool")
            return 1
        for suffix in ("", "-wal", "-shm"):
            Path(f"{db}{suffix}").unlink(missing_ok=True)
        tar.extractall(data, filter="data")
    if data / "csc.db" != db:
        (data / "csc.db").replace(db)
    print(f"Restored {len(names) - 1} key/certificate file(s) and the database from {archive}")
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    command, args = argv[0], argv[1:]
    if command == "restore":
        if len(args) != 1:
            print("usage: admin.py restore FILE.tgz")
            return 2
        return restore(Path(args[0]))

    store = Store(db_path())
    try:
        if command == "users" and not args:
            users(store)
            return 0
        if command == "unlock" and len(args) == 1:
            return unlock(store, args[0])
        if command == "delete-user" and len(args) == 1:
            return delete_user(store, args[0])
        if command == "backup" and len(args) <= 1:
            if args:
                backup(store, Path(args[0]))
            else:
                backup(store, pki.DATA_DIR / "backups", keep=KEEP_BACKUPS)
            return 0
    finally:
        store.close()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
