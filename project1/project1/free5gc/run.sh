#!/usr/bin/env bash

PID_LIST=()

sudo -E ./bin/free5gc-upfd -c ./config/upfcfg.yaml -l ./log/nf/upf.log -g ./log/free5gc.log &
PID_LIST+=($!)

sleep 1

NF_LIST="nrf smf udr pcf nssf"

export GIN_MODE=release

for NF in ${NF_LIST}; do
    ./bin/${NF} &
    PID_LIST+=($!)
    sleep 0.1
done

function terminate()
{
    sudo kill -SIGTERM ${PID_LIST[${#PID_LIST[@]}-2]} ${PID_LIST[${#PID_LIST[@]}-1]}
    sleep 2
}

trap terminate SIGINT
wait ${PID_LIST}
