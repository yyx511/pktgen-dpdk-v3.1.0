#! /bin/sh
./app/app/x86_64-native-linuxapp-gcc/pktgen_server -c 0xff00 -n 2 proc-type auto -w "0000:05:00.1" --socket-mem 2048,2048 --file-prefix pgs -- -N -p 0x08 -m "[9].0" -f test/set_range_p0.pkt 

#-l s_debug.txt
