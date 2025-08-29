FROM ubuntu:18.04@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98

SHELL ["/bin/bash", "-c"]

WORKDIR /poka

RUN apt-get update
RUN apt-get install gdb wget python3 -y

COPY zrq ./zrq
COPY quiz.zrq.0 ./quiz.zrq.0
COPY solve1999.py ./solve1999.py

RUN chmod +x zrq

CMD gdb ./zrq --command="solve1999.py" <<< quiz