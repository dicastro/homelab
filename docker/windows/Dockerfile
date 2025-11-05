# Use the official Python image
FROM python:3.12.3-bookworm

VOLUME /root/work

RUN mkdir -p /etc/ansible

ADD ansible.cfg /etc/ansible/ansible.cfg

ENV ANSIBLE_CONFIG=/etc/ansible/ansible.cfg
ENV ANSIBLE_ROLES_PATH=/root/work/roles
ENV ANSIBLE_VAULT_PASSWORD_FILE=/root/work/.vault-pass
