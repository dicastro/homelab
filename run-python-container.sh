#!/bin/bash

docker run -it --rm -w /home/ansible/work -v "$(pwd)":/home/ansible/work dicastro/python:latest bash
