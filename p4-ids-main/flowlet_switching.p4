/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

#define REGISTER_SIZE 8192
#define TIMESTAMP_WIDTH 48
#define ID_WIDTH 16
// #define FLOWLET_TIMEOUT 48w200000
//#define FLOWLET_TIMEOUT 48
//#define IDLE_TIMEOUT 1000 	// todo: is it one second ?
#define FLOWLET_TIMEOUT 120000000
#define IDLE_TIMEOUT 5000000 // todo: is it one second ?


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  Packet stats  *******************
*************************************************************************/
/*
parser MyPacketStatsParser(packet_in packet, 
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
  register<bit<32>>(2) packet_stats;
  

    state start {
			// sum of packet sizes
			packet_stats.read(meta.tmp_counter, 0);
			meta.tmp_counter = meta.tmp_counter + packet.length();
			packet_stats.write(0, meta.tmp_counter);
			
			// numper of packets	
			packet_stats.read(meta.tmp_counter, 1);
			meta.tmp_counter = meta.tmp_counter + 1;
			packet_stats.write(1, meta.tmp_counter);

        transition parse_ethernet;

    }

    state parse_ethernet {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6 : parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
 
    // MyParser();
 
}
*/


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Todo:
    // 1. change flow_id, based on direction, check BasicPacketInfo.java
    // 2. should we clear the timestamp metrics at every interval while getting data to csv?
   
    register<bit<ID_WIDTH>>(REGISTER_SIZE) flowlet_to_id;
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flowlet_time_stamp;
    

    // DELETE
    register<bit<32>>(4) packet_counters;

    
    // Registers for collecting metrics to identify intrution
    register<bit<64>>(REGISTER_SIZE) flow_psh_counter;
    register<bit<64>>(REGISTER_SIZE) flow_syn_counter;
    register<bit<64>>(REGISTER_SIZE) flow_ack_counter;
    register<bit<64>>(REGISTER_SIZE) flow_total_length;
    register<bit<64>>(REGISTER_SIZE) forward_total_length;
    register<bit<64>>(REGISTER_SIZE) forward_total_packets;
    register<bit<16>>(REGISTER_SIZE) fw_win_byt;
    register<bit<64>>(REGISTER_SIZE) flow_total_packets;
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flow_start_time_stamp;
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flow_current_time_stamp;
    register<bit<64>>(REGISTER_SIZE) flow_duration;
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flow_active_start_time_stamp;
    register<bit<64>>(REGISTER_SIZE) flow_total_active_duration;
    register<bit<64>>(REGISTER_SIZE) flow_total_inactive_duration;
    register<bit<64>>(REGISTER_SIZE) flow_active_segments;
    register<bit<64>>(REGISTER_SIZE) flow_min_duration;
    register<bit<32>>(REGISTER_SIZE) src_ipaddr_cache;
    register<bit<32>>(REGISTER_SIZE) dst_ipaddr_cache;
    register<bit<16>>(REGISTER_SIZE) src_port_cache;
    register<bit<16>>(REGISTER_SIZE) dst_port_cache;
    register<bit<8>>(REGISTER_SIZE)  protocol_cache;
    register<bit<32>>(REGISTER_SIZE) ipaddr_cache;
		
 
    action get_metrics() {
		// if the src_ipaddr is not in cache, add it
		hash(meta.src_ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
			(bit<14>)8192);
		
		hash(meta.dst_ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{hdr.ipv4.dstAddr},
			(bit<14>)8192);
		
		// src_ipaddr_cache.write(meta.src_ipcache_index, hdr.ipv4.srcAddr);

		// find the direction of flow
		// 1. ipaddr_cache holds all the source ipaddress
		// 2. hash (srcAddr, destAddr) and check if srcAddr == cache[hashed_key] -> forward
		//       else backward. If the srcAddr doesn't exist in cache, update the cache
		hash(meta.ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
			(bit<14>)8192);
		ipaddr_cache.read(meta.ipcache_index, meta.ipAddr);
	
//		if (meta.ipAddr == hdr.ipv4.srcAddr) {
//				meta.isForward = 1;  // its a forward packet
//		} else if (meta.ipAddr == 0) { 
//				// it can be a new flow or backward packet 				
//				hash(meta.ipcache_index, HashAlgorithm.crc16,
//					(bit<16>)0,
//					{hdr.ipv4.dstAddr, hdr.ipv4.srcAddr},
//					(bit<14>)8192);
//		}
//		ipaddr_cache.read(meta.ipcache_index, meta.ipAddr);
//		if (meta.ipAddr == hdr.ipv4.dstAddr) {
//				meta.isForward = 0;  // its a backward packet
//		} else {
//				// its a new flow, so a forward packet
//				meta.isForward = 1;
//				meta.ipAddr = hdr.ipv4.srcAddr;
//		}
		
		if (meta.ipAddr == hdr.ipv4.srcAddr || meta.ipAddr == 0) {
				meta.isForward = 1;  // its a forward packet
		} 
		
		// it can be a new flow or backward packet 				
		hash(meta.ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{hdr.ipv4.dstAddr, hdr.ipv4.srcAddr},
			(bit<14>)8192);
		ipaddr_cache.read(meta.ipcache_index, meta.ipAddr);
		if (meta.ipAddr == hdr.ipv4.dstAddr) {
				meta.isForward = 0;  // its a backward packet
		} else {
				// its a new flow, so a forward packet
				meta.isForward = 1;
		}
		
		if(meta.isForward == 1) {
				meta.ipAddr = hdr.ipv4.srcAddr;
				meta.dstAddr = hdr.ipv4.dstAddr;
		} else {
				meta.ipAddr = hdr.ipv4.dstAddr;
				meta.dstAddr = hdr.ipv4.srcAddr;
		}
		
		hash(meta.ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{meta.ipAddr, meta.dstAddr},
			(bit<14>)8192);
		ipaddr_cache.write(meta.ipcache_index, meta.ipAddr);
		// end-of-flow direction	


		// find the register index for this flow
		if (meta.isForward == 1) {
				meta.srcAddr = hdr.ipv4.srcAddr;
				meta.dstAddr = hdr.ipv4.dstAddr;
				meta.srcPort = hdr.tcp.srcPort;
				meta.dstPort = hdr.tcp.dstPort;
		} else {
				meta.srcAddr = hdr.ipv4.dstAddr;
				meta.dstAddr = hdr.ipv4.srcAddr;
				meta.srcPort = hdr.tcp.dstPort;
				meta.dstPort = hdr.tcp.srcPort;
		}	
		
		hash(meta.flowlet_register_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{meta.srcAddr, meta.dstAddr, meta.srcPort, meta.dstPort,hdr.ipv4.protocol},
			(bit<14>)8192);


		// update flowinfo_cache
	    src_ipaddr_cache.write(meta.flowlet_register_index, meta.srcAddr);		
	    dst_ipaddr_cache.write(meta.flowlet_register_index, meta.dstAddr);		
	    src_port_cache.write(meta.flowlet_register_index, meta.srcPort);		
	    dst_port_cache.write(meta.flowlet_register_index, meta.dstPort);		
	    protocol_cache.write(meta.flowlet_register_index, hdr.ipv4.protocol);		

	
		// 1. Per_flow psh counter	
		meta.val = 0;
	    if(hdr.tcp.psh == 1) {
		        meta.val = 1;
		}
		
		flow_psh_counter.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter+ meta.val;
		flow_psh_counter.write(meta.flowlet_register_index, meta.tmp_counter);
		
		// packet_counters.read(meta.tmp_counter, 0);
		// meta.tmp_counter = meta.tmp_counter + meta.val;
		// packet_counters.write(0, meta.tmp_counter);

		// 2. Per_flow syn counter	
		meta.val = 0;
		if(hdr.tcp.syn == 1) {
              meta.val = 1; 
		}
		
		// hash(meta.flowlet_register_index, HashAlgorithm.crc16,
		// 	(bit<16>)0,
		// 	{hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort,hdr.ipv4.protocol},
		// 	(bit<14>)8192);
		flow_syn_counter.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter+ meta.val;
		flow_syn_counter.write(meta.flowlet_register_index, meta.tmp_counter);

		// packet_counters.read(meta.tmp_counter, 1);
		// meta.tmp_counter = meta.tmp_counter + meta.val;
		// packet_counters.write(1, meta.tmp_counter);
		
		// 3. Per_flow ack counter	
		meta.val = 0;
		if(hdr.tcp.ack == 1) {
               meta.val = 1; 
		}
		// packet_counters.read(meta.tmp_counter, 2);
		// meta.tmp_counter = meta.tmp_counter + meta.val;
		// packet_counters.write(2, meta.tmp_counter);
   		
		// hash(meta.flowlet_register_index, HashAlgorithm.crc16,
		// 	(bit<16>)0,
		// 	{hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort,hdr.ipv4.protocol},
		// 	(bit<14>)8192);
		flow_ack_counter.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter + meta.val;
		flow_ack_counter.write(meta.flowlet_register_index, meta.tmp_counter);

		// 4. Average packet size (per flow). taking total packet length and total packet count
		flow_total_length.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter + (bit<64>)hdr.ipv4.totalLen;
		flow_total_length.write(meta.flowlet_register_index, meta.tmp_counter);

		flow_total_packets.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter + 1;
		flow_total_packets.write(meta.flowlet_register_index, meta.tmp_counter);

		// 5. total size of packets in forward direction
		forward_total_length.read(meta.tmp_counter, meta.flowlet_register_index);
		if (meta.isForward == 1) {
				meta.tmp_counter = meta.tmp_counter + (bit<64>)hdr.ipv4.totalLen;
		}
		forward_total_length.write(meta.flowlet_register_index, meta.tmp_counter);
		
		// 6. Init_win_bytes_fwd: number of bytes sent in initial window in forward direction
		fw_win_byt.read(meta.tmpWindow, meta.flowlet_register_index);
		if (meta.isForward ==1 && meta.tmpWindow == 0) {
				meta.tmpWindow = hdr.tcp.window;
		}	
		fw_win_byt.write(meta.flowlet_register_index, meta.tmpWindow);
		meta.tmpWindow = 0;

		// 7. Active mean: mean time a flow is active before becoming idle
		// 8. Active min: minimum time a flow was active before becoming idle
		   // set active_start_time_stamp, if not started
		flow_active_start_time_stamp.read(meta.flowlet_active_start_stamp, meta.flowlet_register_index);
		if(meta.flowlet_active_start_stamp == 0) {
				meta.flowlet_active_start_stamp = standard_metadata.ingress_global_timestamp;
		}	
		flow_active_start_time_stamp.write(meta.flowlet_register_index, meta.flowlet_active_start_stamp);
		
		// 9. Subflow fwd bytes:  Average number of packets in a sub flow in the forward direction
	    // this is an approximation		
		forward_total_packets.read(meta.tmp_counter, meta.flowlet_register_index);
		if (meta.isForward == 1) {
				meta.tmp_counter = meta.tmp_counter + 1;
		}
		forward_total_packets.write(meta.flowlet_register_index, meta.tmp_counter);
		
		// 10. Flow duration: we will capture the start time of the flow and the end time of the flow
		flow_start_time_stamp.read(meta.flowlet_last_stamp, meta.flowlet_register_index);
		if(meta.flowlet_last_stamp == 0) {
				meta.flowlet_last_stamp = standard_metadata.ingress_global_timestamp;
		}	
		flow_start_time_stamp.write(meta.flowlet_register_index, meta.flowlet_last_stamp);
		
	
		meta.val = (bit<64>)(standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp);
		flow_duration.write(meta.flowlet_register_index, meta.val);

		// take copy of previous timestamp and update  register to latest timestamp
		//meta.flowlet_last_stamp = standard_metadata.ingress_global_timestamp;
		flow_current_time_stamp.read(meta.flowlet_last_stamp, meta.flowlet_register_index);
		if(meta.flowlet_last_stamp == 0) {
				meta.flowlet_last_stamp = standard_metadata.ingress_global_timestamp;
		}	
		flow_current_time_stamp.write(meta.flowlet_register_index, standard_metadata.ingress_global_timestamp);

    }
   
    action update_flow_metrics() {
		// take existing active start time
		//flow_active_start_time_stamp.read(meta.flowlet_last_stamp , meta.flowlet_register_index);
		// active flow duration =
		// meta.flowlet_time_diff = standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;
		
		// update min time
		flow_min_duration.read(meta.val, meta.flowlet_register_index);
		if (meta.val > (bit<64>)meta.flowlet_time_diff) {
				meta.val = (bit<64>)meta.flowlet_time_diff;		
		}	
		flow_min_duration.write(meta.flowlet_register_index, meta.val);
		
		// add current active duration
		flow_total_active_duration.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter + (bit<64>)meta.flowlet_time_diff;
		flow_total_active_duration.write(meta.flowlet_register_index, meta.tmp_counter);
			
	
		// add number of segments
		flow_active_segments.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter + 1;
		flow_active_segments.write(meta.flowlet_register_index, meta.tmp_counter);

		// 11. average time between two flows
		flow_total_inactive_duration.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter +  (bit<64>)standard_metadata.ingress_global_timestamp;
		flow_total_inactive_duration.write(meta.flowlet_register_index, meta.tmp_counter);
	
		//  reset the active start time
		flow_active_start_time_stamp.write(meta.flowlet_register_index, standard_metadata.ingress_global_timestamp);
    }

 
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action read_flowlet_registers(){

        //compute register index
        hash(meta.flowlet_register_index, HashAlgorithm.crc16,
            (bit<16>)0,
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort,hdr.ipv4.protocol},
            (bit<14>)8192);

         //Read previous time stamp
        flowlet_time_stamp.read(meta.flowlet_last_stamp, (bit<32>)meta.flowlet_register_index);

        //Read previous flowlet id
        flowlet_to_id.read(meta.flowlet_id, (bit<32>)meta.flowlet_register_index);

        //Update timestamp
        flowlet_time_stamp.write((bit<32>)meta.flowlet_register_index, standard_metadata.ingress_global_timestamp);
    }

    action update_flowlet_id(){
        bit<32> random_t;
        random(random_t, (bit<32>)0, (bit<32>)65000);
        meta.flowlet_id = (bit<16>)random_t;
        flowlet_to_id.write((bit<32>)meta.flowlet_register_index, (bit<16>)meta.flowlet_id);
    }

    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort,
              hdr.ipv4.protocol,
              meta.flowlet_id},
	    num_nhops);

	    meta.ecmp_group_id = ecmp_group_id;
    }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

    }

    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id:    exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
		if (hdr.tcp.isValid()) {
				@atomic {	
						get_metrics();
						meta.flowlet_time_diff = meta.flowlet_last_stamp - meta.flowlet_active_start_stamp;
						meta.flowlet_inactive_time_diff = standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;
						
						// check if inter-packet gap is > 1sec
						if (meta.flowlet_inactive_time_diff > IDLE_TIMEOUT){
							update_flow_metrics();
						}
								
				}
		}

        if (hdr.ipv4.isValid()){

            @atomic {
                read_flowlet_registers();
                meta.flowlet_time_diff = standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;

                //check if inter-packet gap is > 100ms //todo check if the time is milliseconds
                if (meta.flowlet_time_diff > FLOWLET_TIMEOUT){
                    update_flowlet_id();
                }
            }

            switch (ipv4_lpm.apply().action_run){
                ecmp_group: {
                    ecmp_group_to_nhop.apply();
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {

    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}




/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
//MyPacketStatsParser(),
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
