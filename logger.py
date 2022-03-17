import logging


def configure_logging(filename=None):
    if not filename:
        filename = "logs/default.log"
    else:
        filename = "logs/" + filename
    logging.basicConfig(filename=filename,
                        format='%(asctime)s %(levelname)s %(message)s')
