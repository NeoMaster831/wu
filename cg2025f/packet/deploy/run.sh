#!/bin/bash

while true
do
    random_port=$(( ((RANDOM<<15)|RANDOM) % 50000 + 10000 ))
    status="$(nc -z 127.0.0.1 $random_port < /dev/null &>/dev/null; echo $?)"
    if [ "${status}" != "0" ]; then
        echo "$random_port is prob port";
        exec timeout --foreground 120 /home/ctf/prob $random_port;
        echo "prob exit";
        exit;
    fi
done
