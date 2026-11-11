"""basicstation-gate public | signer | issue <eui>"""

import logging
import os
import sys


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO').upper(),
                        format='%(asctime)s %(levelname)-7s %(name)s | %(message)s')
    command, rest = (argv[0], argv[1:]) if argv else ('', [])
    if command == 'public':
        from .public import serve
        serve()
    elif command == 'signer':
        from .signer import serve
        serve()
    elif command == 'issue':
        from .signer import issue_cli
        issue_cli(rest)
    else:
        raise SystemExit(__doc__.strip())


if __name__ == '__main__':
    main()
