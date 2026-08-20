# Container image for the safe-outputs web app (e.g. Google Cloud Run).
#
# Deliberately model-agnostic: the dataset and gateway config are baked in, but
# the LLM endpoint, model id and API key are NOT — they are passed at deploy
# time as environment/secrets (SAFETRE_LLM_BASE_URL / SAFETRE_LLM_MODEL /
# SAFETRE_LLM_API_KEY), so no provider name or secret ever lives in the image.
#
# Build:  docker build -t safetre-web .
# Run:    docker run -p 8080:8080 -e SAFETRE_LLM_BASE_URL=... -e SAFETRE_LLM_MODEL=... \
#                     -e SAFETRE_LLM_API_KEY=... -e SAFETRE_ALLOW_REMOTE_LLM=1 safetre-web
# Cloud Run injects $PORT (8080); the app binds 0.0.0.0:$PORT.

FROM python:3.11-slim

# uv for fast, locked installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
COPY . /app

# Runtime deps only (main + the `web` extra), no dev group.
RUN uv sync --frozen --no-dev --extra web

# Bake a synthetic population into the image so cold starts are fast. Size is a
# build arg: keep it modest for a small instance; raise it for a roomier one.
ARG NIGHTPLAY_PEOPLE=8000
RUN uv run python studies/nightplay/generate.py \
        --out data/nightplay_big --people ${NIGHTPLAY_PEOPLE}

# Gateway config (provider-neutral). The LLM endpoint/model/key and the
# remote-LLM opt-in are supplied at deploy time.
ENV SAFETRE_DATASET=studies/nightplay/nightplay.yaml \
    SAFETRE_DATA_DIR=data/nightplay_big \
    SAFETRE_ANALYST=chimp \
    SAFETRE_CHIMP_MAX_STEPS=8 \
    SAFETRE_QUERY_BUDGET=1000 \
    SAFETRE_SELECTION_BUDGET_BITS=16 \
    SAFETRE_RESTRICTED_CHANNEL=0 \
    SAFETRE_AUDIT_DB=/tmp/audit.db \
    PORT=8080

EXPOSE 8080
CMD ["sh", "-c", "uv run uvicorn safetre_web.app:app --host 0.0.0.0 --port ${PORT:-8080}"]
