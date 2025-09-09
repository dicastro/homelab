# Use the official Python image
FROM python:3.12.3-bookworm

# Create ansible user
RUN groupadd ansible && \
    useradd -m -g ansible ansible

VOLUME /home/ansible/work

RUN mkdir -p /home/ansible/work && \
    chown -R ansible:ansible /home/ansible/work

# Set the user as the default
USER ansible
