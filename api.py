import os

from flask import Flask, request, render_template
from werkzeug import exceptions

from core import (make_urls_from_user_given_domains,
                  make_urls_from_user_given_ips,
                  request_the_api_and_parse_the_content)

app = Flask(__name__)


FLASK_HOST = os.environ.get('FLASK_HOST')

FLASK_PORT = os.environ.get('FLASK_PORT')

BASE_URL = 'http://{}:{}'.format(FLASK_HOST, FLASK_PORT)


@app.errorhandler(exceptions.NotFound)
def handle_page_not(_):
    return render_template('404.html')


@app.errorhandler(exceptions.InternalServerError)
def handle_internal_server_error(error):
    return render_template('index.html', error=' | '.join(error.args))


@app.route("/api", methods=['GET', 'POST'])
def api():
    urls = None

    domains = request.args.get('domain-name')

    if domains:
        urls = make_urls_from_user_given_domains(domains)

    ip_address = request.args.get('ip-address')

    if ip_address:
        urls = make_urls_from_user_given_ips(ip_address)

    if not urls:
        return render_template('index.html')

    result = request_the_api_and_parse_the_content(urls)
    result = filter(lambda record: record['type'] == 'A', result)

    search_term = request.args.get('search-term')

    if search_term:
        search_term = [st.strip() for st in search_term.split(',')]
        result = filter(lambda record: any(map(lambda st: st in record['domain'], search_term)), result)

    return render_template('index.html', result=list(result))


if __name__ == '__main__':
    app.run(host=FLASK_HOST, port=FLASK_HOST)
