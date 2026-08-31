#!/usr/bin/env bash
set -euo pipefail

compose_file="docker-compose.osint.yml"

docker-compose -f "$compose_file" config --quiet

services=(searxng rsshub maigret spiderfoot)
for service in "${services[@]}"; do
  container_id="$(docker-compose -f "$compose_file" ps -q "$service")"
  if [[ -z "$container_id" ]]; then
    echo "FAIL $service: container is not running" >&2
    exit 1
  fi
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id")"
  if [[ "$health" != "healthy" ]]; then
    echo "FAIL $service: $health" >&2
    docker-compose -f "$compose_file" logs --tail=40 "$service" >&2
    exit 1
  fi
  echo "PASS $service: healthy"
done

python3 - <<'PY'
import json
import urllib.request

with urllib.request.urlopen(
    "http://127.0.0.1:8081/search?q=watchtower&format=json", timeout=20
) as response:
    payload = json.load(response)
assert isinstance(payload.get("results"), list), payload
print("PASS searxng: JSON search contract")

for name, url in {
    "rsshub": "http://127.0.0.1:1200/",
    "maigret": "http://127.0.0.1:5000/",
    "spiderfoot": "http://127.0.0.1:5001/",
}.items():
    with urllib.request.urlopen(url, timeout=10) as response:
        assert 200 <= response.status < 400, (name, response.status)
    print(f"PASS {name}: HTTP contract")
PY
