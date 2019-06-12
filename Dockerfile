FROM python:3

RUN apt-get update && \
apt-get -y install automake libtool make gcc python3-pip

WORKDIR /src/cvestack

COPY . ./
RUN pip3 install -r requirements.txt

CMD ["python3", "run.py"]