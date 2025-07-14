FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

ENV PROB_NAME prob
ENV PORT 1337

RUN apt-get update && apt-get install xinetd -y
RUN apt-get install gcc -y

RUN useradd --create-home --shell /bin/bash ctf

WORKDIR /home/ctf/

COPY ./deploy/run.sh ./run.sh
COPY ./deploy/${PROB_NAME} ./${PROB_NAME}
COPY ./deploy/flag ./flag

COPY ctf.xinetd /etc/xinetd.d/ctf
COPY xinetd.conf /etc/xinetd.conf

RUN chmod +x ./run.sh

RUN chown -R root:ctf /home/ctf
RUN chmod -R 750 /home/ctf

EXPOSE ${PORT}
#CMD socat TCP-LISTEN:${PORT},reuseaddr,fork EXEC:./run.sh,stderr
CMD ["/usr/sbin/xinetd", "-dontfork"]
