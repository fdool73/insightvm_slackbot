# Standard Python libraries.
import asyncio
import csv
import datetime
import json
import os
import socket
import sys
import time
import xml.etree.ElementTree as ET

# Third party Python libraries.
import requests

# Custom Python libraries.
import asyncdog
import utility
from secrets import SECRETS


def async_request(api_endpoint):
    """Make an asynchronous request to pull from API end points that have multiple
    pages of data, like '/api/3/vulnerability_exceptions'.  Can also be used for endpoints
    that return less than 500 records, like '/api/3/users'.
    """

    # Make initial request to determine the total_number of pages to retrieve.
    url = '{0}{1}?page=0&size=500'.format(BASE_URL, api_endpoint)
    print("Making initial request to determine the total_number of pages to retrieve: {0}".format(url))
    response = requests.get(url, auth=AUTH, headers=generate_headers())

    # Determine total number of pages that need to be requested.
    page_data = json.loads(response.text)['page']
    total_pages = page_data['totalPages']
    print("Requesting {0} page(s) from API endpoint: {1}".format(total_pages, api_endpoint))

    # Fetch the data.
    loop = asyncio.get_event_loop()
    data_fetcher = asyncdog.DataFetcher(api_endpoint, total_pages)
    future = asyncio.ensure_future(data_fetcher.run())
    all_data = loop.run_until_complete(future)

    print("Retrieved {0} records from API endpoint: {1}".format(len(all_data), api_endpoint))

    return all_data


def retrieve_severe_and_critical_vulnerability_ids_for_asset(asset_id):
    """Retrieve the textual vulnerability IDs (tlsv1_0-enabled) given an asset ID.
    """

    url = '{0}/api/3/assets/{1}/vulnerabilities?page=0&size=500'.format(BASE_URL, asset_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())

    # Asset does not exist.
    if response.status_code == 404:
        print("Asset ID does not exist: {0}".format(asset_id))
        return None

    text_vulnerability_ids = []

    # Asset exists.
    if response.status_code == 200:
        json_response = json.loads(response.text)['resources']

        for vulnerability in json_response:
            text_vulnerability_id = vulnerability['id']

            for item in vulnerability['results']:
                if item['status'] in ['vulnerable', 'vulnerable-version']:
                    severity = retrieve_vulnerability_severity_for_vulnerability_id(text_vulnerability_id)

                    if severity in ['Severe', 'Critical']:
                        # Determine port if it is present.
                        if 'port' not in item:
                            port = ''
                        else:
                            port = item['port']

                        # Determine protocol if it is present.
                        if 'protocol' not in item:
                            protocol = ''
                        else:
                            protocol = item['protocol']

                        text_vulnerability_id_dict = {
                            'text_vulnerability_id': text_vulnerability_id,
                            'port': port,
                            'protocol': protocol,
                            'severity': severity,
                        }

                        text_vulnerability_ids.append(text_vulnerability_id_dict)

        return text_vulnerability_ids


def retrieve_vulnerability_severity_for_vulnerability_id(text_vulnerability_id):
    """Retrieve the criticality value for a text_vulnerability_id
    """

    url = '{0}/api/3/vulnerabilities/{1}'.format(BASE_URL, text_vulnerability_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())

    if response.status_code != 200:
        print("[-] Vulnerability ID '{0}' does not exist.".format(text_vulnerability_id))
        return None

    json_response = json.loads(response.text)
    vulnerability_severity = json_response['severity']

    return vulnerability_severity


def update_insightvm_site_ips(site_id, target_list):
    """Update a InsightVM site with new targets to scan.  Used with ERIS.
    """

    print("[*] Updating assets in site ID: {0}".format(site_id))

    url = '{0}/api/3/sites/{1}/included_targets'.format(BASE_URL, site_id)
    response = requests.put(url, auth=AUTH, json=target_list, headers=generate_headers())

    if response.status_code == 200:
        print("[+] Successfully saved IPs to site: {0} (Site ID: {1})".format(retrieve_site_name_from_site_id(site_id), site_id))
        return True

    else:
        print("[-] Error saving IPs to site: {0} (Site ID: {1})".format(retrieve_site_name_from_site_id(site_id), site_id))
        return False


def retrieve_included_targets_in_site(site_id, verbose=True):
    """Retrieve all the included targets in a site given a site ID.
    """

    if verbose:
        print("[*] Retrieving included targets for site: {0}".format(site_id))

    included_targets = []

    url = '{0}/api/3/sites/{1}/included_targets'.format(BASE_URL, site_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)

    if json_response:
        for target in json_response['addresses']:
            if utility.is_ip_address(target):
                included_targets.append(target)
            elif ' - ' in target:
                # IP range found
                from_ip = target.split(' - ')[0]
                to_ip = target.split(' - ')[1]
                expanded_ips = utility.expand_range_of_ips(from_ip, to_ip, False)
                included_targets += expanded_ips
            else:
                # For hostnames
                included_targets.append(target)

    if verbose:
        print("[*] Found {0} included targets for site: {1}".format(len(included_targets), site_id))

    return included_targets


def retrieve_excluded_targets_in_site(site_id):
    """Retrieve all the excluded targets in a site given a site ID.
    """

    print("[*] Retrieving excluded targets for site: {0}".format(site_id))

    excluded_targets = []

    url = '{0}/api/3/sites/{1}/excluded_targets'.format(BASE_URL, site_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)

    if json_response:
        for target in json_response['addresses']:
            if utility.is_ip_address(target):
                excluded_targets.append(target)
            else:
                # IP range found
                from_ip = target.split(' - ')[0]
                to_ip = target.split(' - ')[1]
                expanded_ips = utility.expand_range_of_ips(from_ip, to_ip)
                excluded_targets += expanded_ips

    print("[*] Found {0} excluded targets for site: {1}".format(len(excluded_targets), site_id))

    return excluded_targets


def retrieve_included_asset_groups_ids_from_site(site_id):
    """Retrieve all included asset group ids given a site ID.
    """

    url = '{0}/api/3/sites/{1}/included_asset_groups'.format(BASE_URL, site_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    included_asset_group_ids = []
    for included_asset_group in json_response:
        included_asset_group_ids.append(included_asset_group['id'])

    return included_asset_group_ids


def retrieve_excluded_asset_groups_ids_from_site(site_id):
    """Retrieve all excluded asset group ids given a site ID.
    """

    url = '{0}/api/3/sites/{1}/excluded_asset_groups'.format(BASE_URL, site_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    excluded_asset_group_ids = []
    for excluded_asset_group in json_response:
        excluded_asset_group_ids.append(excluded_asset_group['id'])

    return excluded_asset_group_ids


def retrieve_asset_ids_in_asset_group(asset_group_id):
    """Retrieve asset ids given a asset group id.
    """

    asset_ids = []

    url = '{0}/api/3/asset_groups/{1}/assets'.format(BASE_URL, asset_group_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)

    if response.status_code == 200:
        if 'resources' in json_response:
            asset_ids = json_response['resources']

    return asset_ids


def retrieve_targets_in_asset_group(asset_group_id, verbose=True):
    """Retrieve all targets in an asset group given an asset group ID.
    """

    if verbose:
        print("[*] Retrieving targets in asset group ID: {0}".format(asset_group_id))

    targets = []

    asset_ids_in_group = retrieve_asset_ids_in_asset_group(asset_group_id)
    for asset_id in asset_ids_in_group:
        url = '{0}/api/3/assets/{1}'.format(BASE_URL, asset_id)
        response = requests.get(url, auth=AUTH, headers=generate_headers())
        json_response = json.loads(response.text)

        for address in json_response['addresses']:
            targets.append(address['ip'])
        targets.append(json_response['hostName'])

    if verbose:
        print("[*] Retrieved {0} targets in asset group ID: {1}".format(len(targets), asset_group_id))

    return targets


def retrieve_sites_all_included_asset_group_targets(site_id):
    """Retrieve all the targets in a site's included asset groups given a site ID.
    """

    sites_all_included_asset_group_targets = []

    included_asset_groups_ids = retrieve_included_asset_groups_ids_from_site(site_id)
    for included_asset_groups_id in included_asset_groups_ids:
        included_asset_group_targets = retrieve_targets_in_asset_group(included_asset_groups_id, False)
        sites_all_included_asset_group_targets += included_asset_group_targets

    return sites_all_included_asset_group_targets


def retrieve_sites_all_excluded_asset_group_targets(site_id):
    """Retrieve all the targets in a site's excluded asset groups given a site ID.
    """
    sites_all_excluded_asset_group_targets = []

    excluded_asset_groups_ids = retrieve_excluded_asset_groups_ids_from_site(site_id)
    for excluded_asset_groups_id in excluded_asset_groups_ids:
        excluded_asset_group_targets = retrieve_targets_in_asset_group(excluded_asset_groups_id)
        sites_all_excluded_asset_group_targets += excluded_asset_group_targets

    return sites_all_excluded_asset_group_targets


def retrieve_site_targets_dictionary_from_site(site_id):
    """Retrieve all included (asset and asset group) targets,
    excluded (asset, asset group, global) targets, and a distilled target list
    given a site ID.
    """
    targets_dict = {}

    included_targets = retrieve_included_targets_in_site(site_id)
    included_asset_group_targets = retrieve_sites_all_included_asset_group_targets(site_id)
    all_included_targets = included_targets + included_asset_group_targets

    excluded_targets = retrieve_excluded_targets_in_site(site_id)
    excluded_asset_group_targets = retrieve_sites_all_excluded_asset_group_targets(site_id)
    global_excluded_targets = retrieve_excluded_global_targets()

    # Combine list of site and global IPs to exclude.
    # TODO does it matter if there are duplicates?  Don't think so right now.
    master_excluded_target_list = excluded_targets + excluded_asset_group_targets + global_excluded_targets

    # Iterate through every included IP.  If it is not in master_excluded_ip_list, add it to distilled_ip_list.
    # distilled_target_list = [ip for ip in all_included_targets if ip not in master_excluded_target_list]
    distilled_target_list = []
    for ip in all_included_targets:
        if (ip not in master_excluded_target_list) and (utility.is_ipv4_address(ip)):
            distilled_target_list.append(ip)

    targets_dict = {
        'included_targets': included_targets,
        'included_asset_group_targets': included_asset_group_targets,
        'all_included_targets': all_included_targets,

        'excluded_targets': excluded_targets,
        'excluded_asset_group_targets': excluded_asset_group_targets,
        'global_excluded_targets': global_excluded_targets,
        'master_excluded_target_list': master_excluded_target_list,

        'distilled_target_list': distilled_target_list
    }

    return targets_dict


def retrieve_excluded_global_targets():
    """A hacky way of pulling the globally excluded IPs and returning a list of
    each individual IP.  Does not query official v3 API endpoint.
    """

    print("[*] Retrieving excluded global targets.")

    # Request is returned as a string of XML.  Can't get it to return proper JSON.
    url = '{0}/data/admin/global-settings'.format(BASE_URL)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    xml_response = response.text
    print(xml_response)
    # Convert string of XML to a proper XML object.
    root = ET.fromstring(xml_response)
    '''
    for child in root[2]:
         print(child.tag, child.attrib)
    ('range', {'from': '10.17.6.166'})
    ('range', {'from': '10.17.6.177'})
    ('range', {'to': '69.20.56.95', 'from': '69.20.56.88'})
    ('range', {'from': '69.20.64.220'})
    ('range', {'from': '69.20.64.232'})
    ('range', {'to': '69.20.75.135', 'from': '69.20.75.128'})
    '''

    global_excluded_targets = []

    # Loop through the exluded IPs and add them to the global_excluded_targets list.
    for child in root[2]:
        # Only 1 IP.  {'from': '10.17.6.177'}
        if len(child.attrib.keys()) == 1:
            from_ip = child.attrib['from']
            global_excluded_targets.append(from_ip)

        # Range of IPs.  {'to': '69.20.56.95', 'from': '69.20.56.88'}
        elif len(child.attrib.keys()) == 2:
            from_ip = child.attrib['from']
            to_ip = child.attrib['to']

            expanded_ips = utility.expand_range_of_ips(from_ip, to_ip)  # noqa
            global_excluded_targets += expanded_ips

        else:
            print("[-] ERROR in retrieve_excluded_global_ips fucntion.")
            sys.exit()

    print("[*] Found {0} global excluded targets.".format(len(global_excluded_targets)))

    return global_excluded_targets


# def retrieve_all_vulnerabilities():
#     """Returns list of vulnerability dictionaries
#     """
#
#     url = '{0}/api/3/vulnerabilities?page=0&size=500'.format(BASE_URL)
#     print("[*] Determining total number of vulnerabilities.")
#     response = requests.get(url, auth=AUTH, headers=generate_headers())
#     json_response = json.loads(response.text)
#
#     if json_response['page']:
#         page = json_response['page']
#         # number = page['number']
#         total_resources = page['totalResources']
#         total_pages = page['totalPages']
#
#     print("[*] Number of vulnerabilities: {0}".format(total_resources))
#
#     i = 0
#     size = 500
#     # remaining = total_resources % size
#
#     # while i < (int(total_resources / size)) + 1:
#     while i < total_pages:
#         url = '{0}/api/3/vulnerabilities?page={1}&size={2}'.format(BASE_URL, i, size)
#         response = c.get(url)
#         i += 1
#
#     print(urls)


def retrive_scan_engine_pool_ids():
    """Retrieve scan engine pool IDs.
    """

    url = '{0}/api/3/scan_engine_pools?page=0&size=500'.format(BASE_URL)

    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    scan_engine_pool_ids = []
    for scan_engine_pool_id in json_response:
        scan_engine_pool_ids.append(scan_engine_pool_id['id'])

    return scan_engine_pool_ids


def engine_check(write_results_to_disk=False):
    """Retrieve engine statuses.
    """

    scan_engine_pool_ids = retrive_scan_engine_pool_ids()

    url = '{0}/api/3/scan_engines?page=0&size=500'.format(BASE_URL)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    engine_array = []

    for scan_engine in json_response:
        # Ignore scan pool IDs and local scan engine.
        if (scan_engine['id'] in scan_engine_pool_ids) or (scan_engine['name'] == 'Local scan engine'):
            continue

        # Check if engine's last refresh date/time was over 3 hours ago.
        stale_engine = datetime.datetime.strptime(scan_engine['lastRefreshedDate'], '%Y-%m-%dT%H:%M:%S.%fZ') < (datetime.datetime.utcnow() - datetime.timedelta(hours=3))

        # Collect engine statuses.
        if stale_engine and scan_engine['name'] != 'Rapid7 Hosted Scan Engine':
            engine_array.append("{0}  --  {1}  --  {2}  --  {3}".format(scan_engine['name'], scan_engine['id'], scan_engine['address'], scan_engine['lastRefreshedDate']))

    if write_results_to_disk:
        with open('engine_check.txt', 'w') as fh:
            fh.write('Engine Check:\n')
            if engine_array:
                fh.write('Engine Name  --  Engine ID  --  Engine Address  --  Engine Status\n')
                for e in engine_array:
                    fh.write(e + '\n')
            else:
                fh.write('All engines are active.\n')

    return engine_array


# def convert_engineer_report_to_dictionary(report_id):
#     """Download a report given a report ID and optional file name.
#     """
#
#     url = '{0}/api/3/reports/{1}/history/latest/output'.format(BASE_URL, report_id)
#     response = requests.get(url, auth=AUTH, headers=generate_headers(), stream=True)
#
#     download_latest_report_from_report_id(report_id, 'report.csv')
#
#
#
#
#     if response.status_code != 200:
#         print("[-] Report ID '{0}' does not exist.".format(report_id))
#         return None


def retrieve_insightvm_usernames():
    """Retrieve the usernames associated with an authentication source.
    """

    url = '{0}/api/3/users?page=0&size=100'.format(BASE_URL)  # BUG for size

    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    usernames = []
    for user in json_response:
        usernames.append(user['login'])

    return usernames


def retrieve_user_id_from_user_name(user_name):
    """Return a user ID given a user name.
    """

    url = '{0}/api/3/users?page=0&size=100'.format(BASE_URL)  # BUG for size

    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    for user in json_response:
        if user['login'] == user_name:
            user_id = user['id']
            print("[+] User '{0}' has user ID: {1}".format(user_name, user_id))
            return user_id

    print("[-] User '{0}' does not exist.".format(user_name))
    return None


def retrieve_user_name_from_user_id(user_id):
    """Return a user name given a user ID.
    """
    url = '{0}/api/3/users/{1}'.format(BASE_URL, user_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())

    if response.status_code != 200:
        print("[-] User ID '{0}' does not exist.".format(user_id))
        return None

    json_response = json.loads(response.text)
    user_name = json_response['login']

    return user_name


def retrieve_asset_group_id_from_asset_group_name(asset_group_name):
    """Return an asset group ID given an asset group name.
    """

    url = '{0}/api/3/asset_groups?page=0&size=500'.format(BASE_URL)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    for asset_group in json_response:
        if asset_group['name'] == asset_group_name:
            asset_group_id = asset_group['id']
            print("[+] Asset group name '{0}' has asset group ID: {1}".format(asset_group_name, asset_group_id))
            return asset_group_id

    print("[-] Asset group name '{0}' does not exist.".format(asset_group_name))
    return None


def retrieve_asset_group_name_from_asset_group_id(asset_group_id):
    """Return an asset group name given an asset group ID.
    """

    url = '{0}/api/3/asset_groups/{1}'.format(BASE_URL, asset_group_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())

    if response.status_code != 200:
        print("[-] Asset Group ID '{0}' does not exist.".format(asset_group_id))
        return None

    json_response = json.loads(response.text)
    asset_group_name = json_response['name']

    return asset_group_name


def retrieve_asset_data_from_asset_id(asset_id):
    """Return an asset data structure given an asset ID.
    """

    url = '{0}/api/3/assets/{1}'.format(BASE_URL, asset_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())

    if response.status_code != 200:
        print("[-] Asset ID '{0}' does not exist.".format(asset_id))
        return None

    json_response = json.loads(response.text)

    return json_response


def retrieve_tags_from_site_id(site_id):
    """Return the tags given a site ID
    """

    url = '{0}/api/3/sites/{1}/tags'.format(BASE_URL, site_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    tags = []
    for tag in json_response:
        tags.append(tag['id'])

    return tags


def retrieve_site_ids_from_tag_id(tag_id):
    """Return site IDs given a tag ID.
    # TODO better checking if tag ID actually exists.
    """

    url = '{0}/api/3/tags/{1}/sites'.format(BASE_URL, tag_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    site_ids = json_response

    return site_ids


def retrieve_tag_id_from_tag_name(tag_name_original):
    """Return a tag ID given a tag name.
    """
    # Remove any white space after tag name and standardize case.
    tag_name = tag_name_original.strip().lower()
    print("[*] Removing whitespace and standardizing case for tag name lookup: '{0}' --> '{1}'".format(tag_name_original, tag_name))

    url = '{0}/api/3/tags?page=0&size=500'.format(BASE_URL)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    for tag in json_response:
        if tag['name'].lower() == tag_name:
            tag_id = tag['id']
            print("[+] Tag name '{0}' has tag ID: {1}".format(tag_name, tag_id))
            return tag_id

    print("[-] Tag name '{0}' does not exist.".format(tag_name))
    return None


def retrieve_site_id_from_site_name(site_name):
    """Return a site id given a site name.
    """

    url = '{0}/api/3/sites?page=0&size=500'.format(BASE_URL)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    for site in json_response:
        if site['name'] == site_name:
            site_id = site['id']
            print("[+] Site '{0}' has site ID: {1}".format(site_name, site_id))
            return site_id

    print("[-] Site '{0}' does not exist.".format(site_name))
    return None


def retrieve_site_name_from_site_id(site_id):
    """Return a site name given a site id.
    """

    url = '{0}/api/3/sites/{1}'.format(BASE_URL, site_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())

    if response.status_code != 200:
        print("[-] Site ID '{0}' does not exist.".format(site_id))
        return None

    json_response = json.loads(response.text)
    site_name = json_response['name']

    return site_name


def retrieve_report_id_from_report_name(report_name):
    """Return the report ID given a report name.
    """

    url = '{0}/api/3/reports?page=0&size=500'.format(BASE_URL)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    for report in json_response:
        if report['name'] == report_name:
            report_id = report['id']
            print("[+] Report '{0}' has report ID: {1}".format(report_name, report_id))
            return report_id

    print("[-] Report '{0}' does not exist.".format(report_name))
    return None


def retrieve_report_name_from_id(report_id):
    """Return the report name given a report ID.
    """

    url = '{0}/api/3/reports/{1}'.format(BASE_URL, report_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)

    if response.status_code != 200:
        print("[-] Report ID '{0}' does not exist.".format(report_id))
        return None

    json_response = json.loads(response.text)
    report_name = json_response['name']

    return report_name


def download_latest_report_from_report_id(report_id, filename='{}.tmp'.format(utility.get_timestamp())):
    """Download a report given a report ID and optional file name.
    """

    url = '{0}/api/3/reports/{1}/history/latest/output'.format(BASE_URL, report_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers(), stream=True)

    if response.status_code != 200:
        print("[-] Report ID '{0}' does not exist.".format(report_id))
        return None

    with open(filename, 'wb') as fh:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:  # Filter out keep-alive new chunks.
                fh.write(chunk)

    if os.path.exists(filename):
        print("[+] Wrote {0} to disk".format(filename))
    else:
        print("[-] Issue writing {0} to disk".format(filename))


def retrieve_report_status(report_id):
    """Return a report status given a report ID.
    """

    url = '{0}/api/3/reports/{1}/history/latest'.format(BASE_URL, report_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())

    if response.status_code != 200:
        print("[-] Report ID '{0}' does not exist.".format(report_id))
        return None

    json_response = json.loads(response.text)
    report_status = json_response['status']

    print("[-] Report ID '{0}' status: {1}".format(report_id, report_status))

    return report_status


def wait_until_report_finishes_being_generated(report_id):
    """Given a report ID, sleep until the report finishes being generated.
    """

    while retrieve_report_status(report_id) == 'started':
        sleep_seconds = 60
        print("[-] Report ID '{0}' is still being generated...sleeping {1} seconds.".format(report_id, sleep_seconds))
        time.sleep(sleep_seconds)


def get_full_engineer_report_name_from_site_name(site_name):
    """Returns the full engineer report name given a site name.
    """
    engineer_csv_report_name = 'Vulnerability Report for Engineers - ' + site_name
    return engineer_csv_report_name


def find_insightvm_report_full_file_path_on_console(report_id):
    """Return the linux file path of the report on disk given the report object.
    """

    url = '{0}/api/3/reports/{1}/history/latest'.format(BASE_URL, report_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)

    if json_response['uri']:
        htroot = '/opt/rapid7/insightvm/nsc/htroot'
        uri = '{0}{1}'.format('/reports/', json_response['uri'].split('/reports/')[1])
        full_file_path = "{0}{1}.gz".format(htroot, uri)
        report_name = retrieve_report_name_from_id(report_id)
        print("\tfull_file_path for '{0}': {1}".format(report_name, full_file_path))
        return full_file_path

    print("[-] No URI for report ID: {0}".format(report_id))
    return None


def populate_vulnerability_ids_from_keystone():
    """Takes the vulnerability_id translation keystone report and converts it to a dictionary.
    """
    print("[*] Populating vulnerability ID dictionary.")
    vuln_ids_dict = {}

    # Find report and gzip decompress to current folder.
    report_name = 'vulnerability_id translation keystone'
    report_id = retrieve_report_id_from_report_name(report_name)

    # Ensure report is not being run.
    wait_until_report_finishes_being_generated(report_id)

    full_path = find_insightvm_report_full_file_path_on_console(report_id)
    keystone_file = 'vulnerability_id_translation_keystone.csv'
    utility.gzip_decompress(full_path, '.', keystone_file)

    with open(keystone_file, 'r') as csvfile:
        csvreader = csv.DictReader(csvfile)
        for row in csvreader:
            new_slugified_vulnerability_id = row['new_slugified_vulnerability_id']
            old_numeric_vulnerability_id = row['old_numeric_vulnerability_id']
            vuln_ids_dict[new_slugified_vulnerability_id] = old_numeric_vulnerability_id

    print("[+] Done populating vulnerability ID dictionary.")
    return vuln_ids_dict


def retrieve_asset_id_from_ip(ip):
    """Retrieve the asset ID given an IP
    """

    search_payload = {
        'filters': [
            {
                "field": 'ip-address',
                'operator': 'is',
                "value": ip,
            }
        ],
        'match': 'all',
    }

    url = '{0}/api/3/assets/search'.format(BASE_URL)
    response = requests.post(url, auth=AUTH, json=search_payload, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    if not json_response:
        print("[-] IP '{0}' does not exist.".format(ip))
        return None

    asset_id = json_response[0]['id']

    return asset_id


def retrieve_all_site_ids():
    """Retrieve all available site IDs as a dictionary of SiteID:Site Name.
    """

    url = '{0}/api/3/sites?size=500'.format(BASE_URL)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)['resources']

    site_ids = {}
    for i in json_response:
        site_ids[i['id']] = i['name']

    return site_ids


def adhoc_site_scan(ip_list, site):
    """Scan a subset of IPs for a given site.
    """

    payload = {
        "hosts": [
        ],
        "name": "Slackbot Scan",
    }

    for ip in ip_list:
        payload['hosts'].append(ip)

    url = '{}/api/3/sites/{}/scans'.format(BASE_URL, site)
    response = requests.post(url, auth=AUTH, json=payload, headers=generate_headers())
    json_response = json.loads(response.text)

    # For some reason, this response code does not match the docs.
    # Docs state you should get a 200 response for a successful scan start
    # Testing indicates the proper response is 201: HTTP CREATED code.
    if not response.status_code == 201:
        raise SystemError(json_response['message'])

    scan_id = json_response['id']

    return scan_id


def retrieve_scan_status(scan_id):
    """Retrieve the status of a specified scan ID.
    """

    url = '{0}/api/3/scans/{1}'.format(BASE_URL, scan_id)
    response = requests.get(url, auth=AUTH, headers=generate_headers())
    json_response = json.loads(response.text)

    # Return more than just the status since there is additional useful info.
    return json_response


def site_membership(site, target_list):
    '''Determines if the provided IP(s)/hostnames are part of a given site. This function
    should be used to loop through a collection (all) sites.
    '''
    targs = retrieve_included_targets_in_site(site, False)
    targs += retrieve_sites_all_included_asset_group_targets(site)
    matches = []
    for address in target_list:
        # IP to IP matching
        if address in targs:
            matches.append((site, address))
        # IP to Hostname Matching
        elif utility.is_ip_address(address):
            try:
                if socket.gethostbyaddr(address)[0] in targs:
                    matches.append((site, socket.gethostbyaddr(address)[0]))
            # Handle unknown host error
            except socket.herror:
                pass
        # Hostname to Hostname matching
        else:
            try:
                hostname = socket.gethostbyname(address)
                if hostname in targs:
                    matches.append((site, hostname))
            # Handle unknown host error
            except socket.gaierror:
                pass

    return matches


def generate_headers():
    header = {
        'Accept': 'application/json',
        'Accept-Encoding': 'deflate, gzip',
        'Accept-Language': 'en-US',
    }

    return header


# Only populate if 'insightvm' key exists.
if 'insightvm' in SECRETS:
    # Build BASE_URL
    BASE_URL = 'https://{0}:{1}'.format(SECRETS['insightvm']['host'], SECRETS['insightvm']['port'])

    # Create requests AUTH object.
    AUTH = requests.auth.HTTPBasicAuth(SECRETS['insightvm']['username'], SECRETS['insightvm']['password'])
