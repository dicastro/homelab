# Homelab

## TODOs

- create playbook to deploy vaultwarden
- create playbook to deploy homeassistant
- migrate data from vaultwarden in homeassistant in rpi
- migrate data from homeassistant in rpi
- create playbook to deploy service to track car expenses
- create playbook to deploy service to track recipes
- create playbook to deploy owncloud
- create playbook to deploy immitch
- check pve bios to see if _Restore on AC Power Loss_ (or similar) is enabled
- create playbook to deploy diun
- create playbook deploy loki
- create playbook to deploy promtail
- create playbook to deploy grafana
- install proxmox backup server in laptop hp envy 17
- create playbook to configure backups for VMs
- create a specific telegram chatbot in order to receive notifications
- update configuration of mailrise in order to use the correct telegram chatbot
- adapt backup folders/files in `download.sh` once the project structure is definitive
- review in detail playbook 10-a-deploy-prometheus.yaml as it is not idempotent, sometimes prometheus-config.yaml is interpreted as directory


## How to download this repo (read-only mode, without `git clone`)

```
> curl -s https://raw.githubusercontent.com/dicastro/homelab/main/download.sh | bash
```

> By running the command above a folder `homelab` will be created relative to the path where the command is being run from

## Prerequisites

This project requires:

- Ansible
- Python 3.12.3

It can be installed locally or through a docker container.

My preferred way is to use a docker container, so everything to run it using a docker container is provided in this repo.

> This README will only provide guides about using docker

## How to install Ansible

### Build docker image

From `docker` path run the `build.sh` script

#### Why building an image?

This is to avoid permission issues. There will be files generated from the docker container image that would be owned by *root* if the python official image is used.

The custom docker image is based in the official python one and adds an *ansible* user with the same `UID` and `GID` than the user in the host machine.

### Run the python container

Run the script `run-python-container.sh` (`run-python-container.cmd` from windows)

> From windows there´s still a permission issues. The mapped volume has 777 permissions by default.
>   - Ansible is ignoring `ansible.cfg` configuration file
>   - The file `.vault-pass` is considered a script as it has execution permission
>   - The keys in `vmssshkey` cannot be used
> So the first time running the container `chmod 644 ansible.cfg .vault-pass` and `chmod 600 output/**/vmssshkey/*` has to be run.

### Create a python virtual environment:

```
> python -m venv <VIRTUAL_ENVIRONMENT_FOLDER>

e.g.
> python -m venv .venv
```

### Activate the python virtual environment

```
> source <VIRTUAL_ENVIRONMENT_FOLDER>/bin/activate

e.g.
> source .venv/bin/activate
```

### Install Ansible

> With the python virtual environment activated

```
(.venv) > pip install ansible
```

## How to deactivate an active python virtual environment

> With the python virtual environment activated

```
(.venv) > deactivate
```

## How to verify all hosts in the inventory are reachable by Ansible

> With the python virtual environment activated

```
(.venv) > ansible -i <PATH_TO_INVENTORY> -m ping all

e.g.
(.venv) > ansible -i inventories/prod/inventory.yaml -m ping all
```

## How to run an Ansible playbook

> With the python virtual environment activated

If there is no encrypted file by ansible-vault involved in the playbook:

```
(.venv) > ansible-playbook -i <PATH_TO_INVENTORY_FILE> <PATH_TO_PLAYBOOK_FILE>
```

If there is an encrypted file by ansible-vault involved in the playbook:

```
(.venv) > ansible-playbook -i <PATH_TO_INVENTORY_FILE> <PATH_TO_PLAYBOOK_FILE> --ask-vault-pass

or

(.venv) > ansible-playbook -i <PATH_TO_INVENTORY_FILE> <PATH_TO_PLAYBOOK_FILE> --vault-password-file .vault-pass
```

> `vault-password-file` can be configured in `ansible.cfg` through the property `vault_password_file`
> ```ini
> [defaults]
> vault_password_file = <PATH_TO_VAULT_PASSWORD_FILE>
> ```

> If ansible command is not run from the same path where `ansible.cfg` is present, its path can be configured through the environment variable `ANSIBLE_CONFIG`.
> ```
> (.venv) > ANSIBLE_CONFIG=<PATH_TO_ANSIBLE_CFG> ansible-playbook -i <PATH_TO_INVENTORY_FILE> <PATH_TO_PLAYBOOK_FILE>`
> ```

## How to encrypt a file with Ansible Vault

```
(.venv) > ansible-vault encrypt <PATH_TO_FILE>

e.g.
(.venv) > ansible-vault encrypt ./inventories/prod/secrets.yaml
```

## How to decrypt a file with Ansible Vault

```
(.venv) > ansible-vault decrypt <PATH_TO_FILE>

e.g.
(.venv) > ansible-vault decrypt ./inventories/prod/secrets.yaml
```

## How to display certificate details

```
openssl x509 -in /etc/docker/certs/ca.pem -noout -text
```

## How to install manually qemu-guest-agent

(This has already been included in the playbook and script to create VMs and has been delegated to cloud-init through custom vendor configuration)

```
apt update && apt install -y qemu-guest-agent && systemctl enable --now qemu-guest-agent
```

## How to flush DNS cache

```
sudo systemd-resolve --flush-caches
```

## How to Render an alertmanager template using `amtool`

Having the `data.json` file placed at `/tmp` with the following contents:

```
{
  "receiver": "telegram-notifications",
  "status": "firing",
  "alerts": [
    {
      "status": "firing",
      "labels": {
        "alertname": "ContainerNotRunning",
        "host": "machine1",
        "instance": "1.2.3.4:9876",
        "job": "nodeexporter",
        "name": "actualbudget",
        "severity": "critical",
        "state": "exited"
      },
      "annotations": {
        "description": "Container 'actualbudget' on host 'machine1' not running ('exited')",
        "summary": "Container not running"
      },
      "startsAt": "2025-07-09T04:48:30.309Z",
      "endsAt": "2025-07-10T06:26:30.309Z",
      "generatorURL": "https://prometheus.domain.com/graph?g0.expr=container_status+%3D%3D+0&g0.tab=1",
      "fingerprint": "a1b2c3d4e5f6a1b2"
    }
  ],
  "groupLabels": {
    "alertname": "ContainerNotRunning"
  },
  "commonLabels": {
    "alertname": "ContainerNotRunning",
    "host": "machine1",
    "instance": "1.2.3.4:9876",
    "job": "nodeexporter",
    "name": "actualbudget",
    "severity": "critical",
    "state": "exited"
  },
  "commonAnnotations": {
    "description": "Container 'actualbudget' on host 'machine1' not running ('exited')",
    "summary": "Container not running"
  },
  "externalURL": "https://prometheus.domain.com",
  "version": "4",
  "groupKey": "{}:{alertname=\"ContainerNotRunning\"}",
  "truncatedAlerts": 0
}
```

Run the following command to render a template:

```
amtool template render --template.glob='/etc/alertmanager/templates/*.tmpl' --template.data=/tmp/data.json --template.text='{{ template "telegram.custom.message" . }}'
```

To debug and display what is loaded in the context when rendering the template:

```
amtool template render --template.glob='/etc/alertmanager/templates/*.tmpl' --template.data='/tmp/data2.json' --template.text='{{ printf "%#v" . }}'
```

## How to reconfigure Proxmox when changing router

If the new router has a different IP (e.g. changing from 192.168.86.1 to 192.168.1.1) the following files have to be modified

- `/etc/network/interfaces`
- `/etc/hosts`
- `/etc/resolv.conf`

## UPS

### How to reset usb of back-ups (BX700va-gr)

[source](https://community.se.com/t5/APC-UPS-for-Home-and-Office-Forum/Lost-USB-comms-after-a-killpower-BX700U/td-p/293653)

1. Disconnect any attached load.
2. Unplug the UPS from the wall socket.
3. Disconnect the UPS' internal battery.
4. Push and hold the "On" button on the UPS for 5 seconds
5. Reconnect internal battery.
6. Plug UPS in to known good power source.
7. Turn UPS on.

### How to list usb devices

To list all usb devices run:

```
> lsusb
```

This is a sample output of the command:

```
Bus 001 Device 001: ID 1a1a:0001 Linux Foundation 3.0 root hub
Bus 002 Device 001: ID 1a2b:0001 American Power Conversion Uninterruptible Power Supply
Bus 003 Device 001: ID 1a3c:0001 MediaTek Inc. Wireless_Device
Bus 004 Device 001: ID 1a4d:0001 Linux Foundation 2.0 root hub
Bus 005 Device 001: ID 1a5e:0001 Linux Foundation 3.0 root hub
Bus 006 Device 001: ID 1a6f:0001 Linux Foundation 2.0 root hub
```

Run the following command to get details of the specific usb device

```
> lsusb -v -s <BUS>:<DEVICE>

e.g.

> lsusb -v -s 2:1
```

### How to get UPS information with nut-client

```
upsc <NUT_SERVER_NAME>@<NUT_SERVER_IP> battery.runtime 2>/dev/null
upsc <NUT_SERVER_NAME>@<NUT_SERVER_IP> battery.charge 2>/dev/null
upsc <NUT_SERVER_NAME>@<NUT_SERVER_IP> battery.charge.low 2>/dev/null
upsc <NUT_SERVER_NAME>@<NUT_SERVER_IP> ups.status 2>/dev/null
upsc <NUT_SERVER_NAME>@<NUT_SERVER_IP> ups.load 2>/dev/null
```

### How to see logs of nut-monitor

```
journalctl -u nut-monitor.service
```

### How to see logs of ups-notify script

```
journalctl -t ups-notify
```

> To follow logs add `-f` to the previous command

### Why `nut-safe-shutdown` C program

The configured script that is executed when there is an UPS event is run with `nut` user. There is some logic in the script to gracefully shut down the host, but this needs root permissions. In proxmox host there is no sudo or possibility to add permissions to `nut` user to be able to shut down the host invoking `/sbin/shutdown` command.

`nut-safe-shutdown` is a C program that fakes that the shutdown is run by root, in this way `nut` user will be able to invoke the script.

> It is important to remark that in order to work, the C program has to be owned by `root:root` and the file mode has to be `4755`.

The C program is not using `/sbin/shutdonw` because it won't work if for example there is any active ssh session. However, using `/bin/systemctl poweroff -i` will do the work independently of the active ssh sessions.