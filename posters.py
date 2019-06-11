import json
import logging
import os
import re
from abc import ABC, abstractmethod
from logging.handlers import SysLogHandler

import requests

from cveparser import CVEParser
from query import Query


def get_cve_generator(config):
    cve_feed_gen = CVEParser(config)
    strip_spaces = config.get('strip_spaces')
    pattern_file = config.get('pattern_file')

    with open(pattern_file) as f:
        requirements_contents = re.split('\r?\n', f.read())
        for requirement in requirements_contents:
            if not requirement or len(requirement.strip()) == 0:
                continue

            if len(requirement) > 1:
                cve_feed_gen.add_desired_query(Query(requirement, strip_padding=strip_spaces))
            else:
                cve_feed_gen.add_desired_query(
                    Query(requirement, strip_padding=strip_spaces))

    return cve_feed_gen


class CVEPoster(ABC):

    def __init__(self, config, name, formatter_func=None):
        self.formatter_func = formatter_func
        self.cve_list = None
        self.old_cve_list = None
        self.cache_file = '.{}_cve_cache'.format(name)
        if os.path.exists(self.cache_file) and os.path.isfile(self.cache_file):
            with open(self.cache_file) as f:
                try:
                    self.old_cve_list = json.loads(f.read())
                except:
                    self.old_cve_list = None

    @abstractmethod
    def post(self, config, cve):
        pass

    def _reload_config(self, config):
        """
        Allows for additional config reload behavior. Called when posting to feed
        """
        pass

    def post_to_feed_if_needed(self, config):
        self._reload_config(config)
        self.cve_list = list(get_cve_generator(config).generate_feed())

        print('Reloaded CVE feeds and patterns. Posting messages if necessary.')
        if self.old_cve_list:
            diffed_list = list(set(self.cve_list) - set(self.old_cve_list))
            for item in diffed_list:
                self.post(config, item)
        else:
            for item in self.cve_list:
                self.post(config, item)

        if self.cve_list:
            self.old_cve_list = self.cve_list
            with open(self.cache_file, 'w+') as f:
                f.write(json.dumps([str(c) for c in self.old_cve_list]))


class SyslogPoster(CVEPoster):

    def __init__(self, config):
        super().__init__(config, 'syslog')

        self.logger = logging.getLogger('CVEStack')
        self.handler_address = config.get('syslog_address')
        self.handler = SysLogHandler(address=self.handler_address)
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.handler)
        self.post_to_feed_if_needed(config)

    def _reload_config(self, config):
        if config.get('syslog_address') != self.handler_address:
            self.logger = logging.getLogger('CVEStack')
            self.handler_address = config.get('syslog_address')
            self.handler = SysLogHandler(address=self.handler_address)
            self.logger.setLevel(logging.DEBUG)
            self.logger.addHandler(self.handler)

    def post(self, config, cve):
        self.logger.info(str(cve))


class SlackPoster(CVEPoster):
    SLACK_TEMPLATE = {
        'username': None,
        'icon_emoji': ':lock:',
        'attachments': [
            {
                'color': '#ff0000',
                'author_name': None,
                'title': None,
                'title_link': None,
                'text': None,
                'fields': [
                    {
                        'title': 'Updated/Created Date',
                        'value': None,
                        'short': False
                    },
                    {
                        'title': 'Keywords matched',
                        'value': None,
                        'short': False
                    }
                ]
            }
        ]
    }

    def _gen_rich_message(self, author_name, username, title, title_link, text, disclosure_date, keywords_matched,
                          emoji=':lock:'):
        result = dict(self.SLACK_TEMPLATE)
        result['icon_emoji'] = emoji
        result['username'] = username
        attachment = result['attachments'][0]
        attachment['author_name'] = author_name
        attachment['author_name'] = author_name
        attachment['title'] = title
        attachment['title_link'] = title_link
        attachment['text'] = text
        attachment['fields'][0]['value'] = disclosure_date
        attachment['fields'][1]['value'] = keywords_matched
        result['attachments'][0] = attachment
        return json.dumps(result)

    def __init__(self, config):
        super().__init__(config, 'slack', self._gen_rich_message)
        self.slack_webhook = config.get('slack_webhook')
        self.post_to_feed_if_needed(config)

    def _reload_config(self, config):
        self.slack_webhook = config.get('slack_webhook')

    def post(self, config, entry):
        cve = entry.feed_entry
        msg = self._gen_rich_message(author_name=config.get('slack_author'),
                                     username=config.get('slack_username'),
                                     title=cve.get('title'),
                                     title_link=cve.get('link'),
                                     text=cve.get('summary'),
                                     disclosure_date=cve.get('updated', cve.get('created', 'Unknown')),
                                     keywords_matched=','.join(entry.matched_on),
                                     emoji=config.get('slack_emoji_icon'))
        response = requests.post(self.slack_webhook, msg)
        response.raise_for_status()


POSTER_TYPES = {
    'slack': SlackPoster,
    'syslog': SyslogPoster
}
