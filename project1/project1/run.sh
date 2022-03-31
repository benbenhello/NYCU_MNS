#!/usr/bin/env bash

SCP=false
BUGNF=false
BIN_AUSF="ausf"
BIN_UDM="udm"

while [[ $1 ]]
do
	case $1 in 
		--with-scp ) SCP=true; shift ;;
		--buggy ) BUGNF=true; shift ;;
		*)
			echo "Usage: $0 [--with-scp] [--buggy]"
			exit 1
	esac
done

CN_IP=`ip address show enp0s8 | grep -o "inet .*" | cut -d'/' -f1 | cut -d' ' -f2`

# Make config
CONFIG="amf smf upf ausf udm"
for nf in $CONFIG
do
	sed "s/<CN_IP>/${CN_IP}/g" free5gc/config/skeleton/${nf}cfg.yaml > free5gc/config/${nf}cfg.yaml
	if [[ $SCP = false ]]
	then
		sed '/scp/d' -i free5gc/config/${nf}cfg.yaml
	fi
done

if $BUGNF
then
	BIN_AUSF="bug_ausf"
	BIN_UDM="bug_udm"
fi

cd ~/project1/free5gc
if $SCP
then
	tmux new-session './run.sh' \
		\; splitw -p 75 "sleep 2 && ./bin/amf" \
		\; splitw -p 33 "sleep 2 && ./bin/${BIN_UDM}" \
		\; splitw -t 0 -h "sleep 2 && ./bin/${BIN_AUSF}" \
		\; splitw -t 3 -h 'sleep 3 && ../scp/bin/scp -c ../scp/config/scpcfg.yaml' \
		\; swap-pane -t 4 -s 2
else
	tmux new-session './run.sh' \
		\; splitw -d "sleep 2 && ./bin/amf" \
		\; splitw -h "sleep 2 && ./bin/${BIN_UDM}" \
		\; splitw -t 2 -h "sleep 2 && ./bin/${BIN_AUSF}"
fi
