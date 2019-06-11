import re

AND_QUERY_RE_STR = '\s*&\s*'


class Query:
    def __init__(self, query, strip_padding=False):
        """
        Initializes a new CVE query object
        :param query: The search string
        :param strip_padding: Should we strip any padding from this query object?
        """
        self.is_negative = False
        self.required_tags = []
        self.left_padded = False
        self.right_padded = False
        self.strip_padding = False

        self.query = query
        # Parse parameters from query
        self.__parse_fields()

        if strip_padding:
            self.query = query.strip()

        if self.left_padded:
            self.query = self.query[2:]
            self.query = ' {}'.format(query.lstrip())
        if self.right_padded:
            self.query = self.query[:-2]
            self.query = '{} '.format(query.rstrip())

    def __parse_fields(self):
        split_query = re.split(AND_QUERY_RE_STR, self.query)
        self.required_tags = [tag.strip() for tag in split_query[1:]]
        self.query = split_query[0]
        self.is_negative = self.query.startswith('-')
        if self.is_negative:
            self.query = self.query[1:]
        self.left_padded = self.query.startswith('__')
        if self.left_padded:
            self.query = self.query[2:]
        self.right_padded = self.query.endswith('__')
        if self.right_padded:
            self.query = self.query[:-2]

    def matches(self, text):
        if not self.is_negative:
            matches = self.query in text
        else:
            matches = self.query not in text
        if matches:
            for extra in self.required_tags:
                tag_is_negative = extra.startswith('-')
                if tag_is_negative:
                    # If our required tag is blacklisted and not in the text
                    extra = extra[1:]
                    matches = extra.lower() not in text
                else:
                    # If our required tag is whitelisted and in the text
                    matches = extra.lower() in text

                if not matches:
                    break

        return matches


