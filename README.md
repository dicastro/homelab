# Homelab

## TODOs

- create playbook deploy-monitoring to deploy prometheus
- update playbook deploy-monitoring to deploy alertmanager
- update playbook deploy-monitoring to deploy loki
- update playbook deploy-monitoring to deploy promtail
- update playbook deploy-monitoring to deploy grafana
- change approach of playbooks to run into localhost and just delegate to specific hosts required tasks
- create a specific telegram chatbot in order to receive notifications
- update configuration of mailrise in order to use the correct telegram chatbot
- adapt backup folders/files in `download.sh` once the project structure is definitive


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

