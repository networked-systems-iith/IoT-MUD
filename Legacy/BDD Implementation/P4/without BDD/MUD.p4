#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

//const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16>  TYPE_TCP  = 6;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
header ethernet_t {
    macAddr_t dEth;
    macAddr_t sEth;
    bit<16>   typeEth;
}
header ipv4_t {
    bit<16>    protocol;
    bit<16>   hdrChecksum;
    bit<8>    ttl;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
header tcp_t{
    bit<48> srcPort;
    bit<48> dstPort;
    bit<16> priority;
    bit<16> checksum;

}
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}
struct metadata {
    /* empty */
    bit<8> state_seth;
    bit<8> state_deth;
    bit<8> state_type;
    bit<8> state_sip;
    bit<8> state_dip;
    bit<8> state_proto;
    bit<8> state_sport;
    bit<8> state_dport;
}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.typeEth){

            TYPE_IPV4: ipv4;
            //TYPE:ipv4;
            default: accept;
        }
    }
    state ipv4 {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            //protocol:6;
            default: accept;
        }
    }
    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }

}
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

 action forward(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.sEth = hdr.ethernet.dEth;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dEth = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;

    }

action drop() {
        mark_to_drop(standard_metadata);
    }
table data{
    key= {
        hdr.ethernet.sEth:ternary;
        hdr.ethernet.dEth:ternary;
        hdr.ethernet.typeEth:ternary;
        hdr.ipv4.srcAddr:ternary;
        hdr.ipv4.dstAddr:ternary;
        hdr.ipv4.protocol:ternary;
        hdr.tcp.srcPort:ternary;
        hdr.tcp.dstPort:ternary;
    }
    actions = {
            
            forward;
            drop;
            NoAction;
           
             //}
    }
     size = 1024;
   default_action =NoAction(); 
    
}
apply {
          
            data.apply();
             
          //}
                     //else if (hdr.tcp.isValid()){
            /* tcp_exact_s.apply();
             tcp_exact_d.apply();
             tcp_exact_prior.apply();*/
          //}
          //meta.result_and =(meta.result_ethernet_source)&(meta.result_ipv4_src)&(meta.result_tcp_s)&(meta.result_ethernet_destination)&(meta.result_ethernet_type)&(meta.result_ipv4_dst)&(meta.result_ipv4_proto)&(meta.result_tcp_d)&(meta.result_tcp_prior);
          // ipv4_exact.apply();)
           //tcp_exact.apply();
           
      }  
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}
/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    /*date_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
           hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);*/
    }
}
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;


