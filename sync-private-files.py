import os
import sys
import argparse
import getpass
from pathlib import Path
import paramiko
from scp import SCPClient


EXPECTED_DIR_NAME = "homelab"

CONTENTS_TO_SYNC = [
    (".ssh", True),                                # folder
    ("inventories/prod", True),                    # folder
    ("output", True),                              # folder
    ("playbooks/files/docker-config.json", False), # file
    (".vault-pass", False),                        # file
    ("notes.md", False),                           # file
]


def check_working_directory():
    cwd = Path.cwd().resolve()
    script_dir = Path(__file__).resolve().parent

    if cwd != script_dir:
        print(f"This script must be run from its own directory:\n  Expected: {script_dir}\n  Got:      {cwd}")
        sys.exit(1)


def connect_ssh(host, port, username, password=None, key_file=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        key_filename=key_file
    )

    return ssh


def push_files(ssh, remote_base_path):
    with SCPClient(ssh.get_transport()) as scp:
        for rel_path, is_dif in CONTENTS_TO_SYNC:
            full_path = Path(rel_path)
            remote_path = os.path.join(remote_base_path, rel_path)

            if not full_path.exists():
                print(f"WARN: Path not found: {rel_path}")
                continue

            if is_dir:
                scp.put(str(full_path), recursive=True, remote_path=os.path.dirname(remote_path))
            else:
                scp.put(str(full_path), remote_path=remote_path)

    print("Push complete!")


def pull_files(ssh, remote_base_path):
    with SCPClient(ssh.get_transport()) as scp:
        for rel_path, is_dir in CONTENTS_TO_SYNC:
            local_path = Path(rel_path)
            remote_path = os.path.join(remote_base_path, rel_path)

            if is_dir:
                scp.get(remote_path, local_path=str(local_path.parent), recursive=True)
            else:
                scp.get(remote_path, local_path=str(local_path))

    print("Pull complete!")


def main():
    parser = argparse.ArgumentParser(description="Sync private homelab files via SSH")
    parser.add_argument("--direction", choices=["push", "pull"], required=True, help="Choose push (to remote) or pull (from remote)")
    parser.add_argument("--host", required=True, help="SSH host")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--remote-path", required=True, help="Remote base path for homelab/")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--key", help="Optional path to private key file")

    args = parser.parse_args()
    check_working_directory()

    password = None
    if not args.key:
        password = getpass.getpass("Enter SSH password: ")

    ssh = connect_ssh(args.host, args.port, args.user, password, args.key)

    try:
        if args.direction == "push":
            push_files(ssh, args.remote_path)
        else:
            pull_files(ssh, args.remote_path)
    finally:
        ssh.close()


if __name__ == "__main__":
    main()
