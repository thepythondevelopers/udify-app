FROM tiangolo/uwsgi-nginx-flask:python3.8

# copy over our requirements.txt file
COPY requirements.txt /tmp/

# upgrade pip and install required python packages
RUN apt-get update
RUN apt-get install -y \
  libev-dev
RUN pip install -U pip
RUN pip install -r /tmp/requirements.txt

WORKDIR ./app
COPY ./app /app
