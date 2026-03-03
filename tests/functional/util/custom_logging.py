import logging
import logging.config
import colorlog
import sys
"""
default configs for the loggers in the rafece2
"""

# Define the format and log colors
log_format = '[%(levelname)s] %(name)s [%(funcName)s:%(lineno)d]: %(message)s'
log_colors = {
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
        }

console_formatter = colorlog.ColoredFormatter(
# Create the ColoredFormatter object
        '%(log_color)s' + log_format,
        log_colors = log_colors
        )

def getLogger(filename):
    logger = logging.getLogger(filename)
    logger.setLevel(logging.DEBUG)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(console_formatter)
    stdout_handler.setLevel(logging.DEBUG)

    logger.addHandler(stdout_handler)
    return logger
