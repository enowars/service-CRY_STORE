FROM python:3.7

WORKDIR /checker

# install requirements
COPY ./requirements.txt /checker/requirements.txt
RUN pip3 install -r requirements.txt

# copy our files in
COPY . ./

# here you might need to add more stuff
#COPY ./checker.py ./checker.privkey ./crypto.py ./

# ENTRYPOINT ["uwsgi", "--uid", "uwsgi", "--socket", "[::]:3031", "--protocol", "http", "--ini", "./uwsgi.ini"]
ENTRYPOINT [ "gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]