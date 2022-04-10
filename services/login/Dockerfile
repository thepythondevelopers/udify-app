# Set base image (host OS)
FROM python:3.8-alpine

# By default, listen on port 5000
EXPOSE 5000/tcp

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file to the working directory
COPY requirements.txt .
RUN apk add libffi-dev
RUN apk add gcc musl-dev python3-dev libffi-dev openssl-dev cargo

# Install any dependencies
RUN pip install -r requirements.txt

# Copy the content of the local src directory to the working directory
COPY ./app /app

# Specify the command to run on container start
CMD [ "python", "./app.py" ]