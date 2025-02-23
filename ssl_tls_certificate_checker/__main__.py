from ssl_tls_certificate_checker import check_multiple_domains

import json
import logging
import sys
from datetime import datetime


def main():
    json_file_name = sys.argv[1]

    alert_time: float
    domains: list
    expiration_datetime: datetime
    # expiration_time: float

    with open(json_file_name, 'r') as json_file:
        data: dict = json.loads(json_file.read())
        alert_time: float = data.get('alert_time', 0)
        domains: list = data.get('domains', [])

        if alert_time == 0:
            logging.warning("The alert time is set to zero. Ensure that the input file is correct.")

        if len(domains) == 0:
            logging.warning("Domains list either was not provided or is not empty.")
            return

    check_multiple_domains(domains, alert_time)


if __name__ == "__main__":
    main()
