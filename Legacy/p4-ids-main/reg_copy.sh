# to copy the register data to file


register_names="flow_psh_counter flow_syn_counter flow_ack_counter flow_total_length forward_total_length forward_total_packets fw_win_byt flow_total_packets flow_start_time_stamp flow_current_time_stamp flow_duration flow_active_start_time_stamp flow_total_active_duration flow_total_inactive_duration flow_active_segments flow_min_duration src_ipaddr_cache dst_ipaddr_cache src_port_cache dst_port_cache protocol_cache ipaddr_cache"

for r in `echo $register_names | awk -F' ' '{for(i=1;i<=NF;i++) print $i}'`
do
	echo "copyind data for register $r to $r.csv"
	echo "register_read $r" | simple_switch_CLI --thrift-port 9090 | grep "=" | cut -d"=" -f2 > $r.csv	      						
	echo $?
done


# convert dec to IP
decIps="src_ipaddr_cache.csv dst_ipaddr_cache.csv"
for r in `echo $decIps | awk -F' ' '{for(i=1;i<=NF;i++) print $i}'`
do
		> "decIP_$r"
		for dip in `cat $r | awk -F',' '{for(i=1;i<=NF;i++) print $i}'`
        do
		    IFS=" " read -r a b c d  <<< $(echo  "obase=256 ; $dip" |bc)
			printf "${a#0}.${b#0}.${c#0}.${d#0}, "  >> "decIP_$r"
        done
done
