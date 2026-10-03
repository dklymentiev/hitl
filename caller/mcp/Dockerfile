FROM python:3.12-slim

# The locked versions, each checked against its hash (ranges are in caller/mcp/requirements.in).
COPY caller/mcp/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt

WORKDIR /app
COPY caller/hitl.py /app/hitl.py
COPY caller/mcp/server.py /app/server.py

ENV HITL_MCP_HOST=0.0.0.0
EXPOSE 8790
# Extra CA certificates mounted into /usr/local/share/ca-certificates are trusted at start.
CMD ["sh", "-c", "update-ca-certificates >/dev/null 2>&1; exec python /app/server.py"]
