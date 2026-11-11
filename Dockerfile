FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir '.[server]' \
    && useradd --create-home --uid 10015 bsg \
    && mkdir -p /state && chown bsg /state
USER bsg
# One image, one role per container: `public` (gateways: 3001, /health on
# 3002) or `signer` (5810, internal only). The signer's keys never belong in a
# container that publishes a port.
EXPOSE 3001 3002 5810
ENTRYPOINT ["basicstation-gate"]
CMD ["public"]
