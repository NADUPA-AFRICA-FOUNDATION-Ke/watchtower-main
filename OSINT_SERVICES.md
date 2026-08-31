# Local open-source OSINT services

These services are for local/pre-production evaluation. Every published port
is bound to `127.0.0.1`; do not expose Maigret or SpiderFoot directly to the
internet without authentication, TLS, rate limiting and an access review.

## Services

| Service | Local URL | Watchtower role |
|---|---|---|
| SearXNG | http://127.0.0.1:8081 | metasearch and indexed social discovery |
| RSSHub | http://127.0.0.1:1200 | creates feeds consumed by the existing RSS adapter |
| Maigret | http://127.0.0.1:5000 | analyst-driven username pivots |
| SpiderFoot | http://127.0.0.1:5001 | analyst-driven infrastructure enrichment |

## Start and verify

```bash
colima start --cpu 4 --memory 8 --disk 30
openssl rand -hex 32  # copy the output to SEARXNG_SECRET in .env
docker-compose -f docker-compose.osint.yml up -d --build
bash scripts/test_osint_services.sh
```

The three registry images are pinned to the exact digests exercised by the
smoke test. SpiderFoot is built from the pinned upstream commit recorded in
the Compose file. Review and retest before intentionally updating any pin.

Stop the stack without deleting investigation data:

```bash
docker-compose -f docker-compose.osint.yml down
```

To delete its local volumes as well, explicitly run `down -v`.

The stack intentionally does not insert Maigret or SpiderFoot findings into
Watchtower automatically. Their output can contain personal data and false
positive identity matches; an analyst must review it before retention.
