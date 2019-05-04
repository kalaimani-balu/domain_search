import json

import requests
from prettytable import PrettyTable
from collections import namedtuple


Record = namedtuple('Record', ('domain', 'ip', 'type'))


def make_urls_from_user_given_domains(input_domains):
    """
    Give the final URLs to be queried against farsight api
    """
    base_url = 'https://farsight-tlb01.threatstream.com/lookup/rrset/name/*.'
    yield from (base_url + str(domain.strip()) for domain in input_domains.split(','))


def request_the_api_and_parse_the_content(urls):
    """
    Yields dictionary with (domain, ip, type) from API response
    """
    headers = {
        'X-API-Key': 'XXXX', 'Accept': 'application/json'
    }

    for url in urls:
        data = requests.get(url, headers=headers)
        error_codes = list(range(400, 600))

        if data.status_code in error_codes:
            print('Error: problem processing url : {}'.format(url))
            print(data.text)
        else:
            # splitting the result lines since the output has multiple JSON lines instead of a single JSON blob.
            records = map(json.loads, data.text.strip().split('\n'))

            yield from map(lambda record: Record(record['rrname'], record['rdata'], record['rrtype']), records)


def get_domain_table(records, search_term=None):
    """
    Pretty prints the all the (Domains, IPs, TYPEs) in table format
    """
    domain_table = PrettyTable()
    domain_table.field_names = ["Domain_Name", "Record_Type", "IP"]

    for record in filter(lambda r: r.type == 'A', records):
        if search_term and search_term not in record.domain:
            continue
        domain_table.add_row([record.domain, record.type, ','.join(record.ip)])

    return domain_table


def main():
    """
    API for CLI mode
    """
    # get the search term from user
    search_input = input("Enter the keyword to search in the resultset: ").strip()

    # get the list of inouts from user and store it as a list
    user_input = input("Enter the list of domains separated by commas: ")

    domains = make_urls_from_user_given_domains(user_input)

    result = list(request_the_api_and_parse_the_content(domains))

    if result:
        print(get_domain_table(result))
        print(get_domain_table(result, search_term=search_input))


if __name__ == '__main__':
    main()
