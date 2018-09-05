"""
main.py

This module implements the main function that executes the processor.
"""
import logging

from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.log import init_console_logging

import handler


def main():
    try:
        init_console_logging(verbose_level=2)
        logger = logging.getLogger(__name__)

        # Start a transaction processor, listening to a given host.
        # TODO: Parameterize this.
        processor = TransactionProcessor(url='tcp://localhost:4004')

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
    main()
