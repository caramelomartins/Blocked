"""
main.py

This module implements the main function that executes the processor.
"""
import argparse
import logging

from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.log import init_console_logging

import handler


def main(url):
    try:
        init_console_logging(verbose_level=2)
        logger = logging.getLogger(__name__)

        # Start a transaction processor, listening to a given host.
        # TODO: Parameterize this.
        processor = TransactionProcessor(url=url)

        # Add custom handler to our TP.
        blocked_handler = handler.BlockedHandler()
        processor.add_handler(blocked_handler)

        # Start TP.
        processor.start()
    except KeyboardInterrupt:
        pass
    except Exception as err:
        print("error: {}".format(err))
    finally:
        if processor is not None:
            processor.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-C', default='tcp://localhost:4004')
    args = parser.parse_args()
    main(args.C)
