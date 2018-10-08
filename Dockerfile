FROM ubuntu:16.04

RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD \
    && echo 'deb http://repo.sawtooth.me/ubuntu/1.0/stable xenial universe' >> /etc/apt/sources.list \
    && apt-get update

RUN apt-get install -y -q python3-sawtooth-sdk python3-pip

WORKDIR /srv
ADD . /srv
RUN pip3 install --no-cache-dir -r requirements.txt 

RUN python3 setup.py install

EXPOSE 4004/tcp

CMD ["python3", "processor/main.py"]
