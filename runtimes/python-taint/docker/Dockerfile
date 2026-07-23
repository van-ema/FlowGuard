FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN python3 -m pip install --upgrade pip \
    && python3 -m pip install openai-agents

WORKDIR /runtime
