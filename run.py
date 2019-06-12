import argparse
import traceback
from time import sleep

import yaml

from posters import POSTER_TYPES

if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Parse a vulnerability feed and look for specific vendors')
    argparser.add_argument('--config-file', '-f', default='config.yml', dest='config_file',
                           help='Sets the location of the configuration file (defaults to "config.yml")')
    args = argparser.parse_args()
    post_interval = 5

    while True:
        with open(args.config_file, 'r') as stream:
            try:
                config = yaml.safe_load(stream)
                outputs = config.get('outputs')
                if not outputs:
                    raise Exception('Invalid configuration! You must set at least one output.')
                cve_posters = []
                for output in outputs:
                    output = output.lower()
                    if output not in POSTER_TYPES:
                        raise Exception('Invalid configuration! Unrecognized output type "{}". Valid types are: {}'
                                        .format(output, POSTER_TYPES.keys()))
                    cve_posters.append(POSTER_TYPES[output](config))
                post_interval = config.get('post_interval')
                for poster in cve_posters:
                    poster.post_to_feed_if_needed(config)
            except Exception as e:
                traceback.print_exc(e)
        sleep(post_interval * 60)
