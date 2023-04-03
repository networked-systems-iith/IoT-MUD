# P4-ids

Steps to generate data:
-----------------------
  1.  Test pcap file tcp_test.pcap is provided in the git repo. 
      This file is created by using following command. \
      ``tcpdump  -qns 0 -X -r ./pcap_splits/test_split_00000_20170704115332.pcap tcp  -w ~/tcp_test.pcap``
  
  2.  place the .p4 files in right environment. we may use exercises in https://github.com/nsg-ethz/p4-learning.git, 01-Reflector exercise will do.
  
  3.  start p4 switch (sudo p4 run)
  
  4.  replay the pcap file\
		`` sudo tcpreplay  --intf1=s1-eth1  ./tcp_pcap/tcp_test.pcap `` \
        `` Actual: 1356 packets (596230 bytes) sent in 157.39 seconds`` \
        `` Rated: 3788.0 Bps, 0.030 Mbps, 8.61 pps``  \
        `` Flows: 113 flows, 0.71 fps, 1356 flow packets, 0 non-flow`` \
        `` Statistics for network device: s1-eth1``  \
        ``        Successful packets:        1356``  \
        ``        Failed packets:            0``     \
        ``        Truncated packets:         0``     \
        ``        Retried packets (ENOBUFS): 0``     \
        ``        Retried packets (EAGAIN):  0``     \
  5. verify if all the packets are received by switch. if not try using --pps(packets per second) option 
     For this verification, we have a counter name packet_counter
		`` simple_switch_CLI --thrift-port 9090 ``   \
        `` Obtaining JSON from switch...        ``  \
        `` Done  							    ``  \
        `` Control utility for runtime P4 table manipulation`` \
        `` RuntimeCmd: register_read packet_counter``          \
        `` register index omitted, reading entire array``      \
        `` packet_counter= 1356`` 							   \
        `` RuntimeCmd:``  									    \
  6. run reg_copy.sh script. this script reads counters from the registers and copies them to .csv files. There will be an individual .csv file for each register.

  7. run p4_data_prep.ipnyb notebook. this will attach all the above csv to one sigle csv
  8. For comparision, there is a CICFlowmeter generated metrics file name tcp_test.pcap_Flow.csv in repo.
