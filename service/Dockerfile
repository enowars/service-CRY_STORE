FROM ubuntu:18.04

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y python3-pip
RUN apt-get install -y socat
RUN apt-get install -y sqlite

RUN python3 -m pip install pycrypto

RUN mkdir /service
WORKDIR /service

COPY cry.py init_client.sql checker.pubkey run.sh ./

RUN groupadd -g 2000 cryptogroup \
&& useradd -m -u 2001 -g cryptogroup cryptodude

RUN chown -R cryptodude /service
RUN chmod +x cry.py run.sh
USER cryptodude

CMD ["/service/run.sh"]