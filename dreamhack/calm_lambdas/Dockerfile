FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

ENV USER chall

USER root
RUN apt-get update && apt-get install -y socat
RUN adduser -u 1337 --disabled-password --gecos "" $USER

USER $USER
WORKDIR /app
COPY ./deploy/main.exe /app
COPY ./deploy/flag /app

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:./main.exe,nofork,stderr"]