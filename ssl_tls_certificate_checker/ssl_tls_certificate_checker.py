import math
import socket
import subprocess
import ssl
from collections.abc import Iterable
from datetime import datetime, timedelta

from cryptography import x509


# https://stackoverflow.com/a/71153638
def get_expiration_datetime(domain: str) -> datetime:
    """
    Gets the datetime at which a certificate will expire.
    :param domain: The domain to check. This can NOT contain a "https://" or "http://".
    :return:
    """

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            print("SSL/TLS version:", ssock.version())

            # get cert in DER format
            data = ssock.getpeercert(True)

            # convert cert to PEM format
            pem_data = ssl.DER_cert_to_PEM_cert(data)

            # pem_data in string. convert to bytes using str.encode()
            # extract cert info from PEM format
            cert_data = x509.load_pem_x509_certificate(str.encode(pem_data))

            return cert_data.not_valid_after_utc


def get_expiration_timestamp(domain: str) -> float:
    """
    Returns the certificates expiration date, but as a timestamp instead of a datetime object.
    :param domain: The domain to check.
    :return:
    """
    return get_expiration_datetime(domain).timestamp()


def sanitize_domain(domain: str) -> str:
    """
    Sanitizes a domain to remove "https://", "http://", and the path.
    :param domain:
    :return:
    """

    # Assuming a domain will be something like https://google.com/
    partially_sanitized = domain.removeprefix("https://").removeprefix("http://")
    domain = partially_sanitized.split("/")[0]

    return domain


def check_domain(domain: str, alert_time: float) -> None:
    """
    Checks a domain's expiration validity. If the certificate is expired, then it will post a notification using the
    `notify-send` command.
    :param domain: The domain to check.
    :param alert_time: The time (in seconds) that an alert should be posted. This is relative, so
    `current_time + alert_time` represents the absolute time that a certificate must be older than.
    :return:
    """

    expiration_datetime = get_expiration_datetime(domain)

    current_datetime = datetime.now()
    # The number of days until a TLS/SSL certificate expires.
    expiration_offset = (expiration_datetime.replace(tzinfo=None) - current_datetime).days
    certificate_expired = expiration_offset <= 0

    if expiration_datetime.timestamp() <= (current_datetime + timedelta(seconds=alert_time)).timestamp():
        subprocess.run(["notify-send", f"SSL/TLS certificate for {domain} "
                                       f"{"expires in" if not certificate_expired else "expired"} "
                                       f"{math.fabs(expiration_offset):.0f} days{"" if not certificate_expired else " ago"}."])


def check_multiple_domains(domains: Iterable, alert_time: float) -> None:
    """
    Checks the expiration validity of multiple certificates. It will post a notification for each certificate that is
    within the `alert_time`. This will automatically sanitize the domain.
    :param domains: An iterable (such as a tuple or a list) containing the domains to validate.
    :param alert_time: The time (in seconds) that an alert should be posted. This is relative, so
    `current_time + alert_time` represents the absolute time that a certificate must be older than.
    :return: None
    """

    for domain in domains:
        check_domain(sanitize_domain(domain), alert_time)
