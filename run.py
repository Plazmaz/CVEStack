import re

import argparse
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

import feedparser
from feedgen.feed import FeedGenerator

from query import Query


class CVEFeedGenerator:

    def __init__(self, cve_feed_url='https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',
                 left_padding=True, right_padding=False,
                 strip_spaces=False):
        self.desired_strings = []
        self.right_padding = right_padding
        self.strip_spaces = strip_spaces
        self.padding = left_padding
        self.cve_feed_url = cve_feed_url
        self._init_feed_gen()

    def _init_feed_gen(self):
        self.fg = FeedGenerator()
        self.fg.link(href='https://web.nvd.nist.gov/view/vuln/search', rel='self')
        self.fg.title('National Vulnerability Database')
        self.fg.description('National Vulnerability Database')
        self.fg.id('https://dylankatz.com/nvd-sorted.xml')

    def add_desired_string(self, string):
        self.desired_strings.append(string)

    def generate_feed(self):
        parsed_feed = feedparser.parse(self.cve_feed_url)
        for entry in parsed_feed.entries:
            for match in self.desired_strings:
                body = entry['summary'].lower()

                if match.query in body:
                    has_all_requirments = True
                    for extra in match.required_tags:
                        if not extra.lower() in body:
                            has_all_requirments = False

                    if not has_all_requirments:
                        continue

                    fe = self.fg.add_entry()
                    fe.id(entry['link'])
                    fe.link(href=entry['link'])
                    fe.description(description=entry.get('description'))
                    fe.title(entry['title'])
                    fe.summary(entry['summary'])
                    fe.comments("CVEStack: Matches '{}'".format(match.query.lower().strip()))
                    fe.updated(datetime.datetime(*entry['updated_parsed'][:7], tzinfo=datetime.tzinfo()))
        rss = self.fg.rss_str(pretty=True)

        # re-init/clear the feed gen
        self._init_feed_gen()
        return rss


def get_cve_generator(pattern_file, left_padding=True, right_padding=False, strip_spaces=False):
    cve_feed_gen = CVEFeedGenerator(left_padding=left_padding, right_padding=right_padding, strip_spaces=strip_spaces)

    with open(pattern_file) as f:
        requirements_contents = re.split('\r?\n', f.read())
        # Generates required version string
        requirements_output = []
        for requirement in requirements_contents:
            if len(requirement.strip()) == 0:
                continue
            if '==' in requirement:
                requirements_output.append(requirement.split('=='))
            else:
                requirements_output.append([requirement])

        for requirement in requirements_output:
            if not requirement or len(requirement) == 0:
                continue
            if len(requirement) > 1:
                cve_feed_gen.add_desired_string(Query(requirement[0], required_tags=requirement[1:],
                                                      left_padded=left_padding, right_padded=right_padding,
                                                      strip_padding=strip_spaces))
            else:
                cve_feed_gen.add_desired_string(Query(requirement[0], left_padded=left_padding, right_padded=right_padding,
                                                      strip_padding=strip_spaces))

    return cve_feed_gen


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Parse a vulnerability feed and look for specific vendors')
    argparser.add_argument('--pattern-file', '-f', default='.dependencies.txt', dest='pattern_file',
                           help='Sets the file to pull patterns from (defaults to ".dependencies.txt")')
    argparser.add_argument('--strip-spaces', '-s', default=False, dest='strip_spaces', action='store_true',
                           help='Sets if spaces should be stripped from patterns (Defaults to false)')
    argparser.add_argument('--left-pad', '-lp', default=True, dest='left_pad_patterns', action='store_true',
                           help='Sets if patterns should be prefixed with a left space (Defaults to true)')
    argparser.add_argument('--right-pad', '-rp', default=False, dest='right_pad_patterns', action='store_true',
                           help='Sets if patterns should be suffixed with a right space (Defaults to false)')
    argparser.add_argument('--port', '-p', default=8088, dest='port', type=int,
                           help='Sets the listening port (defaults to 8088)')
    args = argparser.parse_args()

    class FeedHandler(BaseHTTPRequestHandler):
        last_update = None
        cve_rss = None

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/rss+xml")
            self.end_headers()
            now = datetime.datetime.now()
            if self.last_update is None or (now - FeedHandler.last_update).total_seconds() > 10:
                FeedHandler.cve_rss = (get_cve_generator(args.pattern_file, left_padding=args.left_pad_patterns, right_padding=args.right_pad_patterns, strip_spaces=args.strip_spaces)
                                       .generate_feed())
                self.log_message("%s", "Reloaded CVE feeds and patterns.")
                self.wfile.write(FeedHandler.cve_rss)
                FeedHandler.last_update = now
            else:
                if FeedHandler.cve_rss:
                    self.wfile.write(FeedHandler.cve_rss)


    server = HTTPServer(('localhost', args.port), FeedHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
