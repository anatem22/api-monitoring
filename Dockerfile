FROM /docker-hub/python:3.10-alpine

RUN HTTP_PROXY=$HTTP_PROXY apk add --no-cache curl vim nano

WORKDIR /usr/src/app

RUN pip install --no-cache-dir --upgrade pip
COPY main.py requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN chmod a+x main.py
CMD [ "./main.py" ]
