from flask import Flask, request,render_template

from core import make_urls_from_user_given_domains,request_the_api_and_parse_the_content

app = Flask(__name__)


@app.route("/api")
def api():
    domains = request.args.get('domains')

    if not domains:
        return "At least give one domain name in query params.."

    search_term = request.args.get('search')
    urls = make_urls_from_user_given_domains(domains)
    result = request_the_api_and_parse_the_content(urls)
    result = filter(lambda record: record.type == 'A', result)

    if search_term:
        result = filter(lambda record: search_term in record.domain, result)

    return render_template('index.html', result=result)


if __name__ == '__main__':
    app.run()
