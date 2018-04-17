class Query:
    def __init__(self, query, required_tags=None, left_padded=True, strip_padding=False):
        """
        Initializes a new CVE query object
        :param query: The search string
        :param required_tags: Other strings that must be present to match
        :param strip_padding: Should we strip any padding from this query object?
        :param left_padded: Should this be padded with a space on the left if not already?
        """
        if required_tags is None:
            required_tags = []
        if left_padded:
            self.query = ' {}'.format(query.lstrip())
        if strip_padding:
            self.query = query.strip()
        self.required_tags = required_tags
