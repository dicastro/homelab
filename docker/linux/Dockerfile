# Use the official Python image
FROM python:3.12.3-bookworm

RUN mkdir -p /etc/ansible

ADD ansible.cfg /etc/ansible/ansible.cfg

ENV ANSIBLE_CONFIG=/etc/ansible/ansible.cfg

# Define build arguments for UID and GID
ARG UID
ARG GID

# Create ansible user with the same UID and GID as the host
RUN groupadd -g ${GID} ansible && \
    useradd -m -u ${UID} -g ansible ansible

VOLUME /home/ansible/work

RUN mkdir -p /home/ansible/work && \
    chown -R ansible:ansible /home/ansible/work

ENV ANSIBLE_ROLES_PATH=/home/ansible/work/roles
ENV ANSIBLE_VAULT_PASSWORD_FILE=/home/ansible/work/.vault-pass

# Set the user as the default
USER ansible
