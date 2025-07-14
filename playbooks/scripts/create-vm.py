import os
import sys
import importlib.metadata
import subprocess
import argparse
import json
import traceback


DEFAULT_VM_USER = "root"

REQUIRED_PACKAGES = ["requests", "cryptography"]

SUPPORTED_UBUNTU_VERSIONS = {
    "noble": "24.04"
}

def parse_args():
    parser = argparse.ArgumentParser(description="Create a Proxmox VM")
    parser.add_argument("--base-path", help="Base path to store the ssh-keys", default=".")
    parser.add_argument("--id", required=True, type=int, help="ID for the VM")
    parser.add_argument("--name", required=True, help="Name for the VM")
    parser.add_argument("--ram", type=int, default=2, help="RAM (in GB)")
    parser.add_argument("--cores", type=int, default=1, help="Number of CPU cores")
    parser.add_argument("--disk-size", type=int, default=10, help="Disk size (in GB)")
    parser.add_argument("--storage", default="local-lvm", help="Storage location")
    parser.add_argument("--user", default=DEFAULT_VM_USER, help="VM user")
    parser.add_argument("--password", default=DEFAULT_VM_USER, help="VM password")
    parser.add_argument("--upgrade-packages", action=argparse.BooleanOptionalAction, help="Upgrade packages on first boot")
    parser.add_argument("--ubuntu-codename", choices=SUPPORTED_UBUNTU_VERSIONS.keys(), default="noble", help=f"Ubuntu codename. Supported: {', '.join(SUPPORTED_UBUNTU_VERSIONS.keys())}")
    parser.add_argument("--dhcp", action=argparse.BooleanOptionalAction, help="Use DHCP")
    parser.add_argument("--ip", help="Static IP address")
    parser.add_argument("--gateway-ip", required=True, help="Gateway IP")
    parser.add_argument("--dns-servers", default="1.1.1.1 8.8.8.8", help="DNS servers")
    parser.add_argument("--usb-manufacturer", help="USB manufacturer name (e.g., 'American Power Conversion')")
    parser.add_argument("--usb-product", help="USB product name (e.g., 'Back-UPS 700')")
    parser.add_argument("--proxmox-host", required=True, help="Proxmox hostname or IP")
    parser.add_argument("--proxmox-user", required=True, help="Proxmox user")
    parser.add_argument("--proxmox-auth-realm", choices=["pam", "linux"], default="pam", help="Proxmox authentication realm")
    parser.add_argument("--proxmox-node-name", help="Proxmox node name (if missing, first node will be used by default)")
    parser.add_argument("--output-format", choices=["console", "ansible"], default="console", help="Output format")

    return parser.parse_args()


args = parse_args()

args.proxmox_password = os.getenv("PROXMOX_PASSWORD")

output_format = args.output_format

def is_running_in_venv():
    return (
        hasattr(sys, 'real_prefix')
        or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
        or 'VIRTUAL_ENV' in os.environ
    )


def log_message(message):
    if output_format == "ansible":
        print(f"[INFO] {message}", file=sys.stderr)
    else:
        print(f"[INFO] {message}")


def log_exception(exception, message):
    log_message(f"{message} >> {str(exception)}")

    if output_format == "console":
        traceback.print_exception(type(exception), exception, exception.__traceback__)


def end_script(status, message, changed=False, details=None):
    response = {
        "status": status,
        "message": message,
        "changed": changed,
        "details": details or {},
    }

    if output_format == "ansible":
        print(json.dumps(response))
    else:
        print(f"[{status.upper()}] {message}")
        if details:
            for key, value in details.items():
                print(f"  - {key}: {value}")

    sys.exit(0 if status == "success" else 1)


def install_required_packages_silently(package):
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--quiet", "--no-input", "--disable-pip-version-check", package],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def check_and_install_packages():
    for package in REQUIRED_PACKAGES:
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            log_message(f"Missing package: {package}")
            log_message(f"Installing missing package '{package}'...")
            install_required_packages_silently(package)
        except Exception as e:
            end_script("failure", f"Error checking if package '{package}' is already installed")

if not args.proxmox_password:
    end_script("failure", "Proxmox password is required. Set it via the PROXMOX_PASSWORD environment variable")

if not is_running_in_venv():
    end_script("failure", "This script must be run inside a virtual environment")

# Ensure required packages are installed before continuing
check_and_install_packages()


import re
import time
import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from urllib import parse as urlparse


BASE_SSHKEY_PATH = f"{args.base_path}/vmssshkey"
os.makedirs(BASE_SSHKEY_PATH, exist_ok=True)

KEY_SIZE = 4096
PROXMOX_ISO_PATH = "/var/lib/vz/template/iso"


def get_proxmox_auth(proxmox_host, proxmox_user, proxmox_password, proxmox_auth_realm):
    url = f"https://{proxmox_host}:8006/api2/json/access/ticket"

    payload = {
        "username": f"{proxmox_user}@{proxmox_auth_realm}",
        "password": proxmox_password
    }

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        response = requests.post(url, data=payload, verify=False)

    if response.status_code == 200:
        data = response.json()['data']

        return {
            "ticket": data["ticket"],
            "csrf_token": data["CSRFPreventionToken"]
        }
    else:
        raise Exception(f"Login failed: {response.status_code} - {response.text}")


def proxmox_get(proxmox_host, proxmox_auth, proxmox_endpoint):
    url = f"https://{proxmox_host}:8006/api2/json{proxmox_endpoint}"

    cookies = {"PVEAuthCookie": proxmox_auth["ticket"]}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        response = requests.get(url, cookies=cookies, verify=False)

    if response.status_code == 200:
        return response.json()["data"]
    else:
        raise Exception(f"Proxmox GET request to {proxmox_endpoint} failed: {response.status_code} - {response.text}")


def proxmox_post(proxmox_host, proxmox_auth, proxmox_endpoint, data):
    url = f"https://{proxmox_host}:8006/api2/json{proxmox_endpoint}"

    headers = {"CSRFPreventionToken": proxmox_auth["csrf_token"]}

    cookies = {"PVEAuthCookie": proxmox_auth["ticket"]}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        response = requests.post(url, headers=headers, cookies=cookies, data=data, verify=False)

    if response.status_code == 200:
        return response.json().get("data", {})
    else:
        raise Exception(f"Proxmox POST request to {proxmox_endpoint} failed: {response.status_code} - {response.text}")


def proxmox_put(proxmox_host, proxmox_auth, proxmox_endpoint, data):
    url = f"https://{proxmox_host}:8006/api2/json{proxmox_endpoint}"

    headers = {"CSRFPreventionToken": proxmox_auth["csrf_token"]}

    cookies = {"PVEAuthCookie": proxmox_auth["ticket"]}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        response = requests.put(url, headers=headers, cookies=cookies, data=data, verify=False)

    if response.status_code == 200:
        return response.json().get("data", {})
    else:
        raise Exception(f"Proxmox PUT request to {proxmox_endpoint} failed: {response.status_code} - {response.text}")


def wait_for_proxmox_task(proxmox_host, proxmox_auth, node_name, task_id, task_description):
    log_message(f"Waiting for task: {task_description}")

    while True:
        proxmox_task_response = proxmox_get(proxmox_host, proxmox_auth, f"/nodes/{node_name}/tasks/{task_id}/status")
        task_status = proxmox_task_response['status']

        if task_status in ["stopped", "OK"]:
            log_message("Task completed!")
            break
        elif task_status == "error":
            log_message(f"Task failed with exit status: {proxmox_task_response.get('exitstatus')}")
            break

        time.sleep(5)

    log_message(f"Task completed: {task_description}")


def get_first_node(proxmox_host, proxmox_auth):
    node_list = proxmox_get(proxmox_host, proxmox_auth, "/nodes")

    if not node_list:
        end_script("failure", "No nodes found in Proxmox cluster")

    return node_list[0]["node"]


def validate_vm_exists(proxmox_host, proxmox_auth, vm_id, vm_name):
    vms = proxmox_get(proxmox_host, proxmox_auth, "/cluster/resources?type=vm")

    return any(vm["vmid"] == vm_id or vm["name"] == vm_name for vm in vms)


def ubuntu_image_not_exists(proxmox_host, proxmox_auth, node_name, iso_storage, iso_filename):
    stored_files = proxmox_get(proxmox_host, proxmox_auth, f"/nodes/{node_name}/storage/{iso_storage}/content")

    for file in stored_files:
        if file.get("volid", "").endswith(iso_filename):
            log_message(f"ISO {iso_filename} already exists.")
            return False

    return True


def get_iso_filename(ubuntu_codename):
    ubuntu_version = SUPPORTED_UBUNTU_VERSIONS[ubuntu_codename]
    return f"ubuntu-{ubuntu_version}-server-cloudimg-amd64.img"


def ensure_ubuntu_image(proxmox_host, proxmox_auth, node_name, ubuntu_codename):
    iso_filename = get_iso_filename(ubuntu_codename)
    iso_storage = "local"

    if ubuntu_image_not_exists(proxmox_host, proxmox_auth, node_name, iso_storage, iso_filename):
        image_url = f"https://cloud-images.ubuntu.com/releases/{ubuntu_codename}/release/{iso_filename}"

        log_message(f"Downloading ISO '{image_url}' to Proxmox storage...")

        data = {
            "url": image_url,
            "content": "iso",
            "filename": iso_filename
        }

        download_iso_task = proxmox_post(proxmox_host, proxmox_auth, f"/nodes/{node_name}/storage/local/download-url", data)

        wait_for_proxmox_task(proxmox_host, proxmox_auth, node_name, download_iso_task, f"Download {iso_filename}")

    return f"/var/lib/vz/template/iso/{iso_filename}"


def resize_vm_disk(proxmox_host, proxmox_auth, node_name, vm_id, disk_name, disk_size_gb):
    payload = {
        "disk": disk_name,
        "size": f"{disk_size_gb}G"
    }

    proxmox_put(proxmox_host, proxmox_auth, f"/nodes/{node_name}/qemu/{vm_id}/resize", payload)


def ensure_ssh_key(user):
    ssh_key_path = f"{BASE_SSHKEY_PATH}/id_{user}"
    ssh_pub_key_path = f"{ssh_key_path}.pub"

    if not os.path.exists(ssh_pub_key_path):
        log_message(f"SSH key not found at {ssh_pub_key_path}. Generating new key...")

        try:
            # Generate RSA private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=KEY_SIZE,
                backend=default_backend()
            )

            # Serialize private key
            with open(ssh_key_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )

            os.chmod(ssh_key_path, 0o600)

            # Generate and write public key
            ssh_pub_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode("utf-8")

            # Add default comment
            comment = f"{user}@{output_format}"
            ssh_pub_key_with_comment = f"{ssh_pub_key} {comment}"

            with open(ssh_pub_key_path, "w") as f:
                f.write(ssh_pub_key_with_comment + "\n")

            log_message(f"SSH key generated: {ssh_pub_key_path}")
        except subprocess.CalledProcessError as e:
            log_exception(e, "Error generating SSH key")
            end_script("failure", "Error generating SSH key")
    else:
        log_message(f"SSH key found: {ssh_pub_key_path}")

    with open(ssh_pub_key_path, "r") as f:
        return f.read().strip()


def fuzzy_to_regex(text):
    if not text:
        return None

    #e.g., "Back UPS 700" → ".*Back.*UPS.*700.*"
    parts = re.split(r"\s+", text.strip())

    return ".*" + ".*".join(re.escape(p) for p in parts) + ".*"


def find_usb_device(proxmox_host, proxmox_auth, node_name, manufacturer_match, product_match):
    usb_devices = proxmox_get(proxmox_host, proxmox_auth, f"/nodes/{node_name}/hardware/usb")

    manufacturer_regex = re.compile(fuzzy_to_regex(manufacturer_match), re.IGNORECASE) if manufacturer_match else None
    product_regex = re.compile(fuzzy_to_regex(product_match), re.IGNORECASE) if product_match else None

    matches = []

    for usb_device in usb_devices:
        if manufacturer_regex and not manufacturer_regex.search(usb_device.get("manufacturer", "")):
            continue

        if product_regex and not product_regex.search(usb_device.get("product", "")):
            continue

        matches.append(usb_device)

    if not matches:
        available_devices = ', '.join([f'{usb_device.get("manufacturer")}|{usb_device.get("product")}' for usb_device in usb_devices])

        log_message(f"No USB device matched the given manufacturer/product patterns. Available USB devices: {available_devices}")

        end_script("failure", "No USB device matched the given manufacturer/product patterns.")

    if len(matches) > 1:
        matched_devices = ', '.join([f'{usb_device.get("manufacturer")}|{usb_device.get("product")}' for usb_device in matches])

        log_message(f"Multiple USB devices matched the given manufacturer/product patterns. Please refine your patterns to match only one. Matched USB devices: {matched_devices}")

        end_script("failure", "Multiple USB devices matched. Please refine your patterns to match only one.")

    matched = matches[0]

    return f"{matched['vendid']}:{matched['prodid']}"


def create_vm(proxmox_host, proxmox_auth):
    node_name = get_first_node(proxmox_host, proxmox_auth)

    log_message(f"Using proxmox node: {node_name}")

    vm_id = args.id
    vm_name = args.name
    ram_mb = args.ram * 1024
    storage = args.storage
    user = args.user
    ip = args.ip
    gateway_ip = args.gateway_ip

    if validate_vm_exists(proxmox_host, proxmox_auth, vm_id, vm_name):
        end_script("success", f"VM {vm_name} ({vm_id}) already exists.")

    ubuntu_iso_path = ensure_ubuntu_image(proxmox_host, proxmox_auth, node_name, args.ubuntu_codename)

    # Create VM
    log_message(f"Creating VM {vm_name} ({vm_id})...")

    vm_config = {
        "vmid": vm_id,
        "name": vm_name,
        "memory": ram_mb,
        "cores": args.cores,
        "cpu": "x86-64-v2-AES",
        "net0": "virtio,bridge=vmbr0,firewall=1",
        "ostype": "l26",
        "scsihw": "virtio-scsi-pci",
        "scsi0": f"{storage}:0,import-from={ubuntu_iso_path}",
        "ide2": f"{storage}:cloudinit",
        "boot": "c",
        "bootdisk": "scsi0",
        "agent": 1
    }

    if args.usb_manufacturer or args.usb_product:
        device_id = find_usb_device(proxmox_host, proxmox_auth, node_name, args.usb_manufacturer , args.usb_product)
        usb_param = f"host={device_id}"
        vm_config["usb0"] = usb_param
        log_message(f"USB device passed through configured: usb0: {usb_param}")

    vm_create_task = proxmox_post(proxmox_host, proxmox_auth, f"/nodes/{node_name}/qemu", vm_config)
    wait_for_proxmox_task(proxmox_host, proxmox_auth, node_name, vm_create_task, f"Create VM {vm_name} ({vm_id})")
    log_message(f"Created VM {vm_name} ({vm_id})!")

    resize_vm_disk(proxmox_host, proxmox_auth, node_name, vm_id, "scsi0", args.disk_size)

    # Configure cloud-init
    log_message(f"Configuring Cloud-Init for VM {vm_name}...")
    cloudinit_config = {
        "ciuser": user,
        "cipassword": args.password,
        "sshkeys": urlparse.quote(ensure_ssh_key(user), safe=''),
        "nameserver": args.dns_servers
    }

    if args.dhcp:
        cloudinit_config["ipconfig0"] = "dhcp"
    else:
        if not ip or not gateway_ip:
            end_script("failure", "Static IP and Gateway IP must be provided when DHCP is not used")

        cloudinit_config["ipconfig0"] = f"ip={ip}/24,gw={gateway_ip}"

    proxmox_post(proxmox_host, proxmox_auth, f"/nodes/{node_name}/qemu/{vm_id}/config", cloudinit_config)
    log_message(f"Cloud-Init configured for VM {vm_name}")


    # Start VM
    log_message(f"Starting VM {vm_name}...")
    vm_start_task = proxmox_post(proxmox_host, proxmox_auth, f"/nodes/{node_name}/qemu/{vm_id}/status/start", None)
    wait_for_proxmox_task(proxmox_host, proxmox_auth, node_name, vm_start_task, f"Start VM {vm_name} ({vm_id})")
    log_message(f"VM {vm_name} started")


    end_script("success", f"VM {vm_name} ({vm_id}) created and started", changed=True)


def main():
    proxmox_auth = get_proxmox_auth(args.proxmox_host, args.proxmox_user, args.proxmox_password, args.proxmox_auth_realm)

    try:
        create_vm(args.proxmox_host, proxmox_auth)
    except Exception as e:
        log_exception(e, "failed to create VM")
        end_script("failure", "failed to create VM")


if __name__ == "__main__":
    main()