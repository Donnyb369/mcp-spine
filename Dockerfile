FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY spine/ spine/
COPY configs/ configs/
COPY server.json glama.json ./

RUN pip install --no-cache-dir -e .

# Default: run the Spine with the quickstart config
ENTRYPOINT ["python", "-u", "-m", "spine.cli", "serve", "--config", "configs/quickstart.spine.toml"]
