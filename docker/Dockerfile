# Use the official Python image
FROM python:3.12.3-bookworm

# Define build arguments for UID and GID
ARG UID
ARG GID

# Create the user with the same UID and GID as the host
RUN groupadd -g ${GID} ansible && \
    useradd -m -u ${UID} -g ansible ansible

# Set the user as the default
USER ansible
