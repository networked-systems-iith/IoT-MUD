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
    bit<16> state_seth;
    bit<16> state_deth;
    bit<16> state_type;
    bit<16> state_sip;
    bit<16> state_dip;
    bit<16> state_proto;
    bit<16> state_sport;
    bit<16> state_dport;
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

action store_state_sEth(bit<16> val1)
{
  meta.state_seth = val1;
}
action store_state_dEth(bit<16> val2)
{
  meta.state_deth = val2;
}
action store_state_typEth(bit<16> val3)
{
  meta.state_type = val3;
}
action store_state_proto(bit<16> val4)
{
  meta.state_proto = val4;
}
action store_state_sPort(bit<16> val5)
{
  meta.state_sport = val5;
}
action store_state_dPort(bit<16> val6)
{
  meta.state_dport = val6;
}
action store_state_Source(bit<16> val7)
{
  meta.state_sip = val7;
}
action store_state_Destination(bit<16> val8)
{
  meta.state_dip = val8;
}
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
table sEth_exact{
    key= {
        //hdr.ethernet.dEth:exact;
        hdr.ethernet.sEth:exact;
        //hdr.ethernet.typeEth:exact;
    }
    actions = {
     //@atomic{
            
            store_state_sEth;
            //drop;
            NoAction;
           
             //}
    }
     size = 1024;
   default_action =NoAction(); 
    
}
table sEth_ternary{
    key= {
        hdr.ethernet.sEth:ternary;
    }
    actions = {
            store_state_sEth;
            NoAction;
    }
     size = 1024;
   default_action =NoAction(); 
    
}
table dEth_exact{
    key= {
        meta.state_seth:exact;
        hdr.ethernet.dEth:exact;
        
        
    }
    
actions = {
 
          store_state_dEth;
            drop;
            NoAction;
    }

    size = 1024;
    default_action =NoAction(); 
}
table dEth_ternary{
    key= {
        meta.state_seth:exact;
        hdr.ethernet.dEth:ternary;
        
        
    }
    
actions = {
 
          store_state_dEth;
            drop;
            NoAction;
    }

    size = 1024;
    default_action =NoAction(); 
}
table dEth_default{
    key= {
        meta.state_seth:exact;
        
    }
    
actions = {
 
          store_state_dEth;
            drop;
            NoAction;
    }

    size = 1024;
    default_action =NoAction(); 
}
table typEth_exact{
    key= {
        meta.state_deth:exact;
        hdr.ethernet.typeEth:exact;
        
    }
    
actions = {
 
          store_state_typEth;
           // drop;
            NoAction;
    }

    size = 1024;
    default_action =NoAction(); 
    //default_action = register_action_ethernet_type(1010);
}
table typEth_ternary{
    key= {
        meta.state_deth:exact;
        hdr.ethernet.typeEth:ternary;
        
    }
    
actions = {
 
          store_state_typEth;
            NoAction;
    }

    size = 1024;
    default_action =NoAction();
    } 
 table typEth_default{
    key= {
        meta.state_deth:exact;
        
    }
    
actions = {
 
          store_state_typEth;
            NoAction;
    }

    size = 1024;
    default_action =NoAction();
    } 
table proto_exact{
  key={

    meta.state_type:exact;
    hdr.ipv4.protocol:exact;
  }
  
actions = {
            
            store_state_proto;
            //drop;
            NoAction;
    }

    size = 1024;
    default_action =NoAction();
}
table proto_ternary{
  key={

    meta.state_type:exact;
    hdr.ipv4.protocol:ternary;
  }
  
actions = {
            
            store_state_proto;
            NoAction;
    }

    size = 1024;
    default_action =NoAction();
}
table proto_default{
  key={

    meta.state_type:exact;
  }
  
actions = {
            
            store_state_proto;
            NoAction;
    }

    size = 1024;
    default_action =NoAction();
}
table sPort_exact{
  key={
    meta.state_proto:exact;
    hdr.tcp.srcPort:exact;
    
  }
  actions = {
    store_state_sPort;
    //drop;
    NoAction;
  }
  size = 1024;
  default_action =NoAction();
  //default_action =NoAction(); 
}
table sPort_ternary{
  key={
    meta.state_proto:exact;
    hdr.tcp.srcPort:ternary;
    
  }
  actions = {
    store_state_sPort;
    NoAction;
  }
  size = 1024;
  default_action =NoAction();
}
table sPort_default{
  key={
    meta.state_proto:exact;
    
  }
  actions = {
    store_state_sPort;
    NoAction;
  }
  size = 1024;
  default_action =NoAction();
}
table dPort_exact{
  key={
    meta.state_sport:exact;
    hdr.tcp.dstPort:exact;
  }
  actions = {
    store_state_dPort;
    //drop;
    NoAction;
  }
  size = 1024;
  default_action =NoAction();
  //default_action =NoAction(); 
}
table dPort_ternary{
  key={
    meta.state_sport:exact;
    hdr.tcp.dstPort:ternary;
  }
  actions = {
    store_state_dPort;
    NoAction;
  }
  size = 1024;
  default_action =NoAction();
}

table dPort_default{
  key={
    meta.state_sport:exact;
  }
  actions = {
    store_state_dPort;
    NoAction;
  }
  size = 1024;
  default_action =NoAction();
}
table Source_exact{
  key={
    meta.state_dport:exact;
    hdr.ipv4.srcAddr:exact;
    //hdr.ipv4.protocol:exact;
  }
  actions = {
     //@atomic{
            
            store_state_Source;
            //drop;
            NoAction;
             //}
    }

    size = 1024;
    default_action = NoAction();
    //default_action =NoAction(); 
}
table Source_ternary{
  key={
    meta.state_dport:exact;
    hdr.ipv4.srcAddr:ternary;
  }
  actions = {
     //@atomic{
            
            store_state_Source;
            //drop;
            NoAction;
             //}
    }

    size = 1024;
    default_action = NoAction();
    //default_action =NoAction(); 
}
table Source_default{
  key={
    meta.state_dport:exact;
  }
  actions = {
     //@atomic{
            
            store_state_Source;
            //drop;
            NoAction;
             //}
    }

    size = 1024;
    default_action = NoAction();
    //default_action =NoAction(); 
}
table Destination_exact{
  key={
    meta.state_sip:exact;
    hdr.ipv4.dstAddr:exact;
  }
  
actions = {
            
            store_state_Destination;
            //drop;
            NoAction;
    }

    size = 1024;
  default_action = NoAction();
  //default_action =NoAction(); 
}
table Destination_ternary{
  key={
    meta.state_sip:exact;
    hdr.ipv4.dstAddr:ternary;
  }
  
actions = {
            
            store_state_Destination;
            //drop;
            NoAction;
    }

    size = 1024;
  default_action = NoAction();
  //default_action =NoAction(); 
}
table Destination_default{
  key={
    meta.state_sip:exact;
  }
  
actions = {
            
            store_state_Destination;
            //drop;
            NoAction;
    }

    size = 1024;
  default_action = NoAction();
  //default_action =NoAction(); 
}
table final{
  key ={
    meta.state_dip:exact;

  }
  actions = {
    forward;
    drop;
    NoAction;
  }
  size = 1024;
  default_action = NoAction();
}
apply {
          //if (hdr.ipv4.isValid()){
             /*ipv4_exact_src.apply();
             ipv4_exact_dst.apply();
             ipv4_exact_proto.apply();*/
          //}
          //else if (hdr.ethernet.isValid()){
             sEth_exact.apply();
             sEth_ternary.apply();
             dEth_exact.apply();
             dEth_ternary.apply();
             dEth_default.apply();
             typEth_exact.apply();
             typEth_ternary.apply();
             typEth_default.apply();
             proto_exact.apply();
             proto_ternary.apply();
             proto_default.apply();
             sPort_exact.apply();
             sPort_ternary.apply();
             sPort_default.apply();
             dPort_exact.apply();
             dPort_ternary.apply();
             dPort_default.apply();
             Source_exact.apply();
             Source_ternary.apply();
             Source_default.apply();
             Destination_exact.apply();
             Destination_ternary.apply();
             Destination_default.apply();
             final.apply();
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


