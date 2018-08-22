# Standard Python libraries.
import email
import logging
import gzip
import ipaddress
import os
import smtplib
import time

from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Third party Python libraries.


# Custom Python libraries.
from secrets import SECRETS


def csv_list(sample_string):
    """Convert to lowercase string, split as list, remove duplicates using set, and convert back to a list.
    """
    return list(set(sample_string.lower().split(',')))


def is_ip_address(ip):
    """Takes an IP address returns true or false if it is a valid IPv4 or IPv6 address
    """

    ip = str(ip)

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


def is_ipv4_address(ip):
    """Takes an IP address returns true or false if it is a valid IPv4.
    """

    ip = str(ip)

    try:
        if ipaddress.ip_address(ip).version == 4:
            return True

        elif ipaddress.ip_address(ip).version == 6:
            return False

    except ValueError as e:
        print('[-] {0}'.format(e))


def get_timestamp():
    """Generates a timestamp
    """
    now = time.localtime()
    timestamp = time.strftime('%Y%m%d_%H%M%S', now)
    return timestamp


# http://cmikavac.net/2011/09/11/how-to-generate-an-ip-range-list-in-python/
def expand_range_of_ips(start_ip, end_ip, verbose=True):
    """Takes an IP range and returns all the IPs in that range.
    """

    ip_range = []

    if (ipaddress.ip_address(start_ip).version == 6) or (ipaddress.ip_address(end_ip).version == 6):
        if verbose:
            print("[-] IPv6 IP range not supported in this function: {0} - {1}".format(start_ip, end_ip))
        return ip_range

    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start

    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i - 1] += 1
        ip_range.append(".".join(map(str, temp)))

    return ip_range


def gzip_decompress(gz_file, dest_folder, new_file_name):
    """Decompress a gz file to a specified destination with a specified file name.
    """
    decompressed_gzip_file = os.path.join(dest_folder, new_file_name)
    with open(decompressed_gzip_file, 'wb') as fh:
        with gzip.open(gz_file, 'rb') as gzf:
            file_content = gzf.read()
            fh.write(file_content)


def send_email(to_addresses,  # This is expecting a comma separated string, not a list.
               subject='',
               body='',
               attachments={},
               from_address=SECRETS['email']['from_address'],
               smtp_server=SECRETS['email']['smtp_server'],
               port=25,
               debug=False):
    """Specifies the default email config, and sends an email. Returns True
    if the email is sent successfully, False otherwise.
    """

    if not isinstance(to_addresses, str):
        logging.error("Utility Helper Error: Receivers' addresses must be a comma separated string of addresses.")
        return False

    if not isinstance(from_address, str):
        logging.error("Utility Helper Error: From address must be a string.")
        return False

    # Create a server instance.
    server = smtplib.SMTP(smtp_server, port)

    # Enable debugging option.
    if debug:
        server.set_debuglevel(True)

    message = MIMEMultipart()
    message['From'] = from_address
    message['To'] = to_addresses
    message['Subject'] = subject

    for a in attachments:
        file = MIMEBase('application', 'octet-stream')
        try:
            with open(attachments[a]) as f:
                file.set_payload(f.read())
                file.add_header('Content-Disposition', 'attachment',
                                filename=os.path.basename(attachments[a]))
        except (FileNotFoundError, OSError, ValueError):
            file.set_payload(attachments[a])
            file.add_header('Content-Disposition', 'attachment',
                            filename=a)

        email.encoders.encode_base64(file)
        message.attach(file)

    message.attach(MIMEText(body))

    try:
        server.sendmail(from_address, to_addresses.split(','), message.as_string())
        server.quit()
    except Exception as e:
        logging.error("Error sending email: {}".format(e))
        return False

    return True
