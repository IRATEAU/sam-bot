# Use the official Python image from the Docker Hub
FROM python:3.8

# These two environment variables prevent __pycache__/ files.
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN git clone https://github.com/yaleman/sam-bot /code/

WORKDIR /code

RUN git checkout docker

RUN pip install -r requirements.txt


#COPY *.py /code/
COPY config.json /code/

CMD python main.py
