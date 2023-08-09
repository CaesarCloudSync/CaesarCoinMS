FROM python:3.8-slim-buster

WORKDIR /python-docker

RUN apt update
RUN sudo apt-get upgrade -y
RUN apt-get install python3-pip python-dev-is-python3 libmysqlclient-dev
RUN apt-get install -y gcc default-libmysqlclient-dev pkg-config 
RUN rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .
EXPOSE 80
ENTRYPOINT python app.py