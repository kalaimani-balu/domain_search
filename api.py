from flask import Flask, request, render_template

from core import (make_urls_from_user_given_domains,
                  request_the_api_and_parse_the_content,
                  get_domain_table_as_html)

app = Flask(__name__)


@app.context_processor
def utility_processor():
    def format_table(df):
        return df.to_html(index=False, classes='table table-striped table-hover')
    return dict(format_table=format_table)


@app.route("/api")
def api():
    domains = request.args.get('domains')

    if not domains:
        return "At least give one domain name in query params.."

    search_term = request.args.get('search')
    urls = make_urls_from_user_given_domains(domains)
    result = request_the_api_and_parse_the_content(urls)

    return render_template('index.html', result=get_domain_table_as_html(result, search_term))


if __name__ == '__main__':
    app.run()
