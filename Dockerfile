FROM python:3

ENV PYTHONUNBUFFERED 1

ARG API_KEY

ENV API_KEY ${API_KEY}

RUN mkdir /code

WORKDIR /code

COPY requirements.txt /code/

RUN pip install -r requirements.txt

COPY . /code/