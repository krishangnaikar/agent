FROM python:3.10.5-slim-buster

RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install supervisor
RUN apt-get -y install vim

WORKDIR /app

COPY . .

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN pip install -r requirement.txt

CMD ["/usr/bin/supervisord"]
