"""Pinned, bounded HTTP transport for the existing synchronous monitor clients."""
from __future__ import annotations
import socket
import httpcore
import httpx
from watchtower.discovery.safe_fetch import _public_ip


class PublicNetworkBackend(httpcore.NetworkBackend):
    def __init__(self):
        self.backend = httpcore.SyncBackend()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host.lower().rstrip('.') in {'localhost', 'localhost.localdomain'}:
            raise httpcore.ConnectError('private target rejected')
        addresses = sorted({str(row[4][0]) for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        if not addresses or not all(_public_ip(address) for address in addresses):
            raise httpcore.ConnectError('non-public target rejected')
        # Connect to the validated IP, never resolve the original hostname twice.
        return self.backend.connect_tcp(addresses[0], port, timeout, local_address, socket_options)

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError('unix sockets are forbidden')


class BoundedSyncStream(httpx.SyncByteStream):
    def __init__(self, stream, limit=4_000_000):
        self.stream, self.limit = stream, limit

    def __iter__(self):
        size = 0
        for chunk in self.stream:
            size += len(chunk)
            if size > self.limit:
                raise httpx.ReadError('response exceeds size limit')
            yield chunk

    def close(self):
        self.stream.close()


class PublicHTTPTransport(httpx.HTTPTransport):
    def __init__(self):
        super().__init__(trust_env=False)
        self._pool._network_backend = PublicNetworkBackend()

    def handle_request(self, request):
        if request.url.scheme not in {'https', 'http'} or request.url.userinfo:
            raise httpx.InvalidURL('invalid public URL')
        response = super().handle_request(request)
        response.stream = BoundedSyncStream(response.stream)
        return response
