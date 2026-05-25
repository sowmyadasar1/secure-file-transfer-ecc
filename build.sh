#!/usr/bin/env bash
# Render build script for the FastAPI backend
set -o errexit

pip install --upgrade pip
pip install -r backend/requirements.txt
pip install httpx
