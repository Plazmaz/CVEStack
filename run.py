import re
import yaml

import argparse
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

import feedparser
from feedgen.feed import FeedGenerator

from query import Query


class CVEFeedGenerator:

    def __init__(self, config):
        self.config = config
        self.desired_strings = []
        self.right_padding = config.get('right_padding')
        self.left_padding = config.get('left_padding')
        self.strip_spaces = config.get('strip_spaces')
        self.cve_feed_urls = config.get('feed_lists')
        self._init_feed_gen()

    def _init_feed_gen(self):
        self.fg = FeedGenerator()
        self.fg.link(href=self.config.get('rebroadcast_self'), rel='self')
        self.fg.title(self.config.get('rebroadcast_title'))
        self.fg.description(self.config.get('rebroadcast_description'))
        self.fg.id(self.config.get('rebroadcast_id`'))

    def add_desired_string(self, string):
        self.desired_strings.append(string)

    def generate_feed(self):
        for cve_feed_url in self.cve_feed_urls:
            parsed_feed = feedparser.parse(cve_feed_url)
            for entry in parsed_feed.entries:
                for match in self.desired_strings:
                    full_text = entry['title'].lower() + '\n' + entry['summary'].lower()

                    if match.query in full_text:
                        has_all_requirments = True
                        for extra in match.required_tags:
                            if not extra.lower() in full_text:
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


def get_cve_generator(config):
    cve_feed_gen = CVEFeedGenerator(config)
    left_padding = config.get('left_padding')
    right_padding = config.get('right_padding')
    strip_spaces = config.get('strip_spaces')
    pattern_file = config.get('pattern_file')
    
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
    argparser.add_argument('--config-file', '-f', default='config.yml', dest='config_file',
                           help='Sets the file to pull patterns from (defaults to ".dependencies.txt")')
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
                with open(args.config_file, 'r') as stream:
                    try:
                        config = yaml.safe_load(stream)
                        FeedHandler.cve_rss = (get_cve_generator(config).generate_feed())
                    except yaml.YAMLError as exc:
                        print(exc)
                self.log_message("%s", "Reloaded CVE feeds and patterns.")
                self.wfile.write(FeedHandler.cve_rss)
                FeedHandler.last_update = now
            else:
                if FeedHandler.cve_rss:
                    self.wfile.write(FeedHandler.cve_rss)

    
    with open(args.config_file, 'r') as stream:
        try:
            config = yaml.safe_load(stream)
            FeedHandler.cve_rss = (get_cve_generator(config).generate_feed())
        except yaml.YAMLError as exc:
            print(exc)
    server = HTTPServer((config.get('listening_host'), config.get('port')), FeedHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
