import json

import os
import requests
from prettytable import PrettyTable

API_KEY = os.environ.get('API_KEY')

if not API_KEY:
    raise SystemExit('[ERROR] Set the environment variable "APK_KEY" before starting the application.')


def make_urls_from_user_given_domains(input_domains):
    """
    Give the final URLs to be queried against farsight api
    """
    base_url = 'https://farsight-tlb01.threatstream.com/lookup/rrset/name/'
    yield from (base_url + str(domain.strip()) for domain in input_domains.split(','))


def make_urls_from_user_given_ips(input_ips):
    """
    Give the final URLs to be queried against farsight api
    """
    base_url = 'https://farsight-tlb01.threatstream.com/lookup/rdata/ip/'
    yield from (base_url + str(domain.strip()) for domain in input_ips.split(','))


def request_the_api_and_parse_the_content(urls):
    """
    Yields dictionary with (domain, ip, type) from API response
    """
    headers = {'X-API-Key': API_KEY, 'Accept': 'application/json'}

    def extract_data(record):
        return {'domain': record['rrname'].strip('.'),
                'ip': record['rdata'],
                'type': record['rrtype'],
                'single': isinstance(record['rdata'], str)}

    for url in urls:
        data = requests.get(url, headers=headers)
        error_codes = list(range(400, 600))

        if data.status_code in error_codes:
            raise requests.exceptions.HTTPError(data.text)

        records = map(json.loads, data.text.strip().split('\n'))
        yield from map(extract_data, records)


def get_domain_table(result, search_term=None):
    """
    Pretty prints the all the (Domains, IPs, TYPEs) in table format
    """
    domain_table = PrettyTable()
    domain_table.field_names = ["Domain_Name", "Record_Type", "IP"]

    result = filter(lambda r: r['type'] == 'A', result)

    if search_term:
        search_term = [st.strip() for st in search_term.split(',')]
        result = filter(lambda r: any(map(lambda st: st in r['domain'], search_term)), result)

    for record in result:
        domain_table.add_row([record['domain'],
                              record['type'],
                              ', '.join(record['ip']) if not record['single'] else record['ip']])

    return domain_table


def main():
    """
    API for CLI mode
    """
    # get the list of inputs from user and store it as a list
    user_input = input("Enter the list of domains separated by commas: ")

    # get the search term from user
    search_input = input("Enter the keyword to search in the result set: ").strip()

    urls = make_urls_from_user_given_domains(user_input)

    result = list(request_the_api_and_parse_the_content(urls))

    if result:
        print(get_domain_table(result, search_term=search_input))


if __name__ == '__main__':
    main()
