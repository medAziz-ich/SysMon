#!/usr/bin/env python3
"""
migrate_passwords.py
====================
One-time migration: upgrades all dashboard_users rows whose password_hash
is a plain SHA-256 hex digest (64 chars) to a bcrypt hash.

Because we don't have the original plaintext passwords we can't re-hash them
directly.  Instead this script resets every legacy-hashed account to a
temporary password you supply, which the user must change on next login.

Usage:
    python3 migrate_passwords.py [--db sysmon.db] [--temp-password "NewPass123!"]

The script is idempotent — accounts already using bcrypt are left untouched.
"""
import sys, re, sqlite3, argparse, secrets, string
import bcrypt

SHA256_RE = re.compile(r'^[a-f0-9]{64}$')

def generate_temp_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def migrate(db_path: str, temp_password: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    users = conn.execute("SELECT id, username, password_hash FROM dashboard_users").fetchall()

    migrated = []
    skipped  = []

    for user in users:
        h = user["password_hash"]
        if SHA256_RE.match(h):
            new_hash = bcrypt.hashpw(temp_password.encode(), bcrypt.gensalt(rounds=12)).decode()
            conn.execute("UPDATE dashboard_users SET password_hash=? WHERE id=?",
                         (new_hash, user["id"]))
            migrated.append(user["username"])
        else:
            skipped.append(user["username"])

    conn.commit()
    conn.close()

    print(f"\n✔ Migration complete")
    print(f"  Migrated  ({len(migrated)}): {', '.join(migrated) if migrated else 'none'}")
    print(f"  Skipped   ({len(skipped)}):  {', '.join(skipped) if skipped else 'none'} (already bcrypt)")
    if migrated:
        print(f"\n⚠  Temporary password set for migrated accounts: {temp_password!r}")
        print("   Share it with affected users and ask them to change it immediately.")

def main():
    parser = argparse.ArgumentParser(description="Migrate SHA-256 password hashes to bcrypt")
    parser.add_argument("--db",            default="sysmon.db",  help="Path to sysmon.db")
    parser.add_argument("--temp-password", default=None,         help="Temporary password for migrated accounts")
    args = parser.parse_args()

    temp = args.temp_password or generate_temp_password()
    print(f"Using DB: {args.db}")
    migrate(args.db, temp)

if __name__ == "__main__":
    main()
