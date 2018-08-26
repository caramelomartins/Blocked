import logging

from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.log import init_console_logging

from handler import BlockedHandler


def main():
    try:
        init_console_logging(verbose_level=2)

        logger = logging.getLogger(__name__)
        logger.debug('started main')

        processor = TransactionProcessor(url='tcp://localhost:4004')
        handler = BlockedHandler()
        processor.add_handler(handler)
        processor.start()
    except KeyboardInterrupt:
        pass
    except Exception as err:  # pylint: disable=broad-except
        print("Error: {}".format(err))
    finally:
        if processor is not None:
            processor.stop()


if __name__ == '__main__':
    main()
