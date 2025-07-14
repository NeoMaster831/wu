FROM ubuntu:22.04

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install xinetd -y
RUN apt-get install gcc -y
RUN apt-get install libssl-dev -y
RUN apt-get install python3-pip -y
RUN pip install pwntools


RUN useradd -ms /bin/bash ctf

WORKDIR /home/ctf

ADD ./server.c /home/ctf
ADD ./execute.py /home/ctf/
ADD ./start.sh /home/ctf/
ADD ./payload.py /home/ctf/
RUN gcc ./server.c -lcrypto -lssl -o ./server
RUN rm ./server.c

RUN chown -R root:ctf /home/ctf
RUN chmod -R 750 /home/ctf
RUN chmod -R 770 /home/ctf/payload.py
RUN chmod -R 710 /home/ctf/server
RUN chmod -R 770 /home/ctf/start.sh

ADD ./robotsig.xinetd /etc/xinetd.d/robotsig

USER ctf

CMD ["/usr/sbin/xinetd", "-dontfork"]
