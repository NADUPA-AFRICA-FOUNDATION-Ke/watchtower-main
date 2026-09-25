"""Optional no-key repository and archive adapters."""
from __future__ import annotations
from investigation.models import Entity, Evidence, Relationship
from investigation.extraction import extract_entities
from .base import ProviderRun, SourceHealth
from .providers import HttpProvider, _finish


class GitHubPublicProvider(HttpProvider):
    name = 'github_public'

    def capabilities(self):
        return ('repository_search',)

    async def discover(self, context):
        self.min_interval = 6
        key = f'{context.query}|{context.max_results}'
        data = self.cache.get(self.name, key)
        if data is None:
            data = await self._json('GET', 'https://api.github.com/search/repositories',
                                    params={'q': context.query[:200], 'per_page': min(30, context.max_results)},
                                    headers={'Accept': 'application/vnd.github+json'})
            if not isinstance(data, dict) or not isinstance(data.get('items'), list):
                raise ValueError('malformed repository response')
            self.cache.put(self.name, key, data, 3600)
        run = ProviderRun(SourceHealth(self.name, 'limited' if data.get('incomplete_results') or data.get('total_count', 0) > len(data['items']) else 'operational',
                                       tuple(self.capabilities()), detail='Public repository metadata; code search is not performed'))
        for row in data['items']:
            name, url = row.get('full_name'), row.get('html_url')
            if not name or not url:
                run.health.status = 'limited'
                continue
            repository = Entity('repository', 'github:' + name.lower(), name, 'github')
            ev = Evidence(context.investigation_id, repository.id, self.name, 'repository_observation', name, url, row, 0.9,
                          source_published_at=row.get('created_at'))
            run.entities.append(repository)
            run.evidence.append(ev)
            for child in extract_entities((row.get('description') or '') + ' ' + (row.get('homepage') or '')):
                run.entities.append(child)
                run.relationships.append(Relationship(context.investigation_id, repository.id, child.id, 'mentions', 0.8, ev.id))
        return _finish(self, run)


class WaybackProvider(HttpProvider):
    name = 'wayback'

    def capabilities(self):
        return ('historical_web', 'url_discovery')

    async def enrich(self, entity, context):
        key = f'{entity.canonical_value}|{context.max_results}'
        rows = self.cache.get(self.name, key)
        if rows is None:
            rows = await self._json('GET', 'https://web.archive.org/cdx/search/cdx', params={
                'url': entity.canonical_value + '/*', 'output': 'json', 'filter': 'statuscode:200',
                'fl': 'timestamp,original,digest', 'collapse': 'urlkey', 'limit': context.max_results,
            })
            if not isinstance(rows, list) or rows and rows[0] != ['timestamp', 'original', 'digest']:
                raise ValueError('malformed archive response')
            self.cache.put(self.name, key, rows, 86400)
        run = ProviderRun(SourceHealth(self.name, 'limited' if len(rows) > context.max_results else 'operational',
                                       tuple(self.capabilities()), detail='Archived captures; not evidence of current page contents'))
        for row in rows[1:]:
            if not isinstance(row, list) or len(row) != 3:
                run.health.status = 'limited'
                continue
            timestamp, url, digest = row
            from investigation.normalization import normalize_url
            target = Entity('url', normalize_url(url), url)
            ev = Evidence(context.investigation_id, target.id, self.name, 'archive_observation', url,
                          'https://web.archive.org/web/' + timestamp + '/' + url,
                          {'capture_timestamp': timestamp, 'archive_digest': digest}, 0.9)
            run.entities.append(target)
            run.evidence.append(ev)
            run.relationships.append(Relationship(context.investigation_id, entity.id, target.id, 'observed_in', 0.9, ev.id))
        return _finish(self, run)
