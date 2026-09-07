"""A directory-listing server that writes its hrefs as absolute paths.

Apache's mod_autoindex and nginx's autoindex both emit *relative* hrefs
("objects/"). Plenty of other servers and reverse proxies emit root-relative
ones ("/.git/objects/") instead, and both spellings are legal HTML that mean
exactly the same thing.

That difference is not cosmetic to a pillager: GitHacker 1.1.10 lost every
subdirectory of the listing against this dialect (issue #82), which no
scenario in this matrix could see, because both servers it tested emit the
same relative form. This scenario isolates that one variable — same repo,
same "Index of" title a pillager looks for, only the href spelling differs.
"""

from __future__ import annotations

import html
import http.server
import os
import socketserver
import urllib.parse
from io import BytesIO

ROOT = os.environ.get('REPO_ROOT', '/srv/repo')
PORT = int(os.environ.get('PORT', '80'))


class Handler(http.server.SimpleHTTPRequestHandler):
    server_version = 'AbsoluteHrefIndex/1.0'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def list_directory(self, path):
        try:
            entries = sorted(os.listdir(path))
        except OSError:
            self.send_error(404, 'No permission to list directory')
            return None
        # The request path is what makes each href absolute.
        base = urllib.parse.unquote(self.path)
        if not base.endswith('/'):
            base += '/'
        body = [
            '<!DOCTYPE html>',
            f'<html><head><title>Index of {html.escape(base)}</title></head>',
            f'<body><h1>Index of {html.escape(base)}</h1><hr><pre>',
            '<a href="../">../</a>',
        ]
        for name in entries:
            is_dir = os.path.isdir(os.path.join(path, name))
            display = name + ('/' if is_dir else '')
            href = base + urllib.parse.quote(name) + ('/' if is_dir else '')
            body.append(f'<a href="{href}">{html.escape(display)}</a>')
        body.append('</pre><hr></body></html>')
        encoded = '\n'.join(body).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        return BytesIO(encoded)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == '__main__':
    with Server(('0.0.0.0', PORT), Handler) as httpd:  # noqa: S104
        httpd.serve_forever()
