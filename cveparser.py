import json

import feedparser

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


def _gen_rich_message(author_name, username, title, title_link, text, disclosure_date, keywords_matched,
                      emoji=':lock:'):
    result = dict(SLACK_TEMPLATE)
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


class CVEEntry(object):
    def __init__(self, feed_entry, matched_on):
        self.feed_entry = feed_entry
        self.matched_on = matched_on

    def __repr__(self):
        json_obj = dict(self.feed_entry)
        json_obj['matches'] = self.matched_on
        return json.dumps(json_obj)


class CVEParser(object):

    def __init__(self, config):
        self.config = config
        self.required_queries = []
        self.strip_spaces = config.get('strip_spaces')
        self.cve_feed_urls = config.get('feed_lists')

    def add_desired_query(self, query):
        self.required_queries.append(query)

    def generate_feed(self):
        for cve_feed_url in self.cve_feed_urls:
            parsed_feed = feedparser.parse(cve_feed_url)
            for entry in parsed_feed.entries:
                matches = []
                for match in self.required_queries:
                    full_text = entry['title'].lower() + '\n' + entry['summary'].lower()

                    if match.matches(full_text):
                        matches.append(match.query.lower().strip())
                if len(matches) == 0:
                    continue
                yield CVEEntry(entry, matches)
