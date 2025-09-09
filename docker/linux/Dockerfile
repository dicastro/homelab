# Use the official Python image
FROM python:3.12.3-bookworm

# Define build arguments for UID and GID
ARG UID
ARG GID

# Create ansible user with the same UID and GID as the host
RUN groupadd -g ${GID} ansible && \
    useradd -m -u ${UID} -g ansible ansible

VOLUME /home/ansible/work

RUN mkdir -p /home/ansible/work && \
    chown -R ansible:ansible /home/ansible/work

# Set the user as the default
USER ansible
