FROM ubuntu:18.04

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y python3-pip
RUN apt-get install -y socat
RUN apt-get install -y sqlite

RUN python3 -m pip install pycrypto

RUN mkdir /service
WORKDIR /service

COPY cry.py init_client.sql run.sh checker.pubkey ./

RUN groupadd -g 2000 cryptogroup \
&& useradd -m -u 2001 -g cryptogroup cryptodude

RUN chown -R cryptodude /service
RUN chmod +x run.sh
USER cryptodude

ENTRYPOINT ["/service/run.sh"]