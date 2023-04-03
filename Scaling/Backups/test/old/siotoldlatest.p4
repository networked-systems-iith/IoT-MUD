#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

//const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x888e;
const bit<16> TYPE_IPV7 = 0x0006;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<8>  TYPE_ICMP  = 1;
const bit<8>  TYPE_IGMP  = 2;
const bit<8>  TYPE_IPV6frag  = 44;
const bit<8>  TYPE_IPV6icmp  = 58;
const bit<8>  TYPE_HOPORT  = 0;
//const bit<8> state_default = 0;



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
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
header ipv6_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
header ipv7_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
header tcp_t{
	//bit reduction
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;

}
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}
header icmp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}
header igmp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}
header ipv6frag_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}
header ipv6icmp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}
header hoport_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    ipv7_t       ipv7;
    tcp_t        tcp;
    udp_t        udp;
    icmp_t       icmp;
    igmp_t       igmp;
    ipv6frag_t   ipv6frag;
    ipv6icmp_t   ipv6icmp;
    hoport_t     hoport;
}
struct metadata {
    /* empty */
    bit<16> state_smac;
    bit<16> state_dmac;
    bit<16> state_type;
    bit<16> state_sip;
    bit<16> state_dip;
    bit<16> state_proto;
    bit<16> state_sport;
    bit<16> state_dport;
    bit<16> state_default;
    bit<16> sport;
    bit<16> dport;
    bit<8> protocol;
    bit<32> sip;
    bit<32> dip;
    //bit<16> state_smac_default;
    bit<8> flag_smac;
    bit<8> flag_dmac;
    bit<8> flag_type;
    bit<8> flag_sip;
    bit<8> flag_dip;
    bit<8> flag_proto;
    bit<8> flag_sport;
    bit<8> flag_dport; 
    
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
            TYPE_IPV6: ipv6;
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            TYPE_ICMP:icmp;
            TYPE_IGMP:igmp;
            TYPE_IPV6frag:ipv6frag;
            TYPE_IPV6icmp:ipv6icmp;
            TYPE_HOPORT:hoport;
            default: accept;

        }
    }
    state ipv6 {
        packet.extract(hdr.ipv6);

        transition select(hdr.ipv6.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            TYPE_ICMP:icmp;
            TYPE_IGMP:igmp;
            TYPE_IPV6frag:ipv6frag;
            TYPE_IPV6icmp:ipv6icmp;
            TYPE_HOPORT:hoport;
            default: accept;

        }
    }
    
    state ipv7 {
        packet.extract(hdr.ipv7);

        transition select(hdr.ipv7.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            TYPE_ICMP:icmp;
            TYPE_IGMP:igmp;
            TYPE_IPV6frag:ipv6frag;
            TYPE_IPV6icmp:ipv6icmp;
            TYPE_HOPORT:hoport;
            default: accept;

        }
    }
    
    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
    state udp {
       packet.extract(hdr.udp);
       transition accept;
    }
    state icmp {
       packet.extract(hdr.icmp);
       transition accept;
    }
    state igmp {
       packet.extract(hdr.igmp);
       transition accept;
    }
    state ipv6frag {
       packet.extract(hdr.ipv6frag);
       transition accept;
    }
    state ipv6icmp {
       packet.extract(hdr.ipv6icmp);
       transition accept;
    }
    state hoport {
       packet.extract(hdr.hoport);
       transition accept;
    }
//Addition of UDP header
	//meta.flag=0;
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
//meta.flag=0;

action store_state_sMAC(bit<16> val1)
{
  meta.flag_smac = 1;
  meta.state_smac = val1;
}
action store_state_sMAC_default(bit<16> val9)
{
  meta.state_default = val9;
}
action store_state_sMAC_default1(bit<16> val10)
{
	meta.flag_smac=0;
	meta.state_smac=val10;
}
action store_state_dMAC(bit<16> val2)
{
  meta.flag_dmac = 1;
  meta.state_dmac = val2;
}
action store_state_dMAC_default(bit<16> val11)
{
	meta.flag_dmac=0;
	meta.state_dmac=val11;
}
action store_state_typEth(bit<16> val3)
{
  meta.flag_type = 1;
  meta.state_type = val3;
}
action store_state_typEth_default(bit<16> val12)
{
	meta.flag_type=0;
	meta.state_type=val12;
}
action store_state_proto(bit<16> val4)
{
  meta.flag_proto = 1;
  meta.state_proto = val4;
}
action store_state_proto_default(bit<16> val13)
{
	meta.flag_proto=0;
	meta.state_proto=val13;
}
action store_state_sPort(bit<16> val5)
{
  meta.flag_sport = 1;
  meta.state_sport = val5;
}
action store_state_sPort_default(bit<16> val14)
{
	meta.flag_sport=0;
	meta.state_sport=val14;
}
action store_state_dPort(bit<16> val6)
{
  meta.flag_dport = 1;
  meta.state_dport = val6;
}
action store_state_dPort_default(bit<16> val15)
{
	meta.flag_dport=0;
	meta.state_dport=val15;
}
action store_state_srcIP(bit<16> val7)
{
  meta.flag_sip = 1;
  meta.state_sip = val7;
}
action store_state_srcIP_default(bit<16> val16)
{
	meta.flag_sip=0;
	meta.state_sip=val16;
}
action store_state_dstIP(bit<16> val8)
{
  meta.flag_dip = 1;
  meta.state_dip = val8;
}
action store_state_dstIP_default(bit<16> val17)
{
	meta.flag_dip=0;
	meta.state_dip=val17;
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
table sMAC_exact{
    key= {
        //hdr.ethernet.dEth:exact;
        hdr.ethernet.sEth:exact;
        //hdr.ethernet.typeEth:exact;
    }
    actions = {
     //@atomic{
            
            store_state_sMAC;
            store_state_sMAC_default;
            //drop;
            //NoAction;
           
             //}
    }
     size = 1024;
   default_action =store_state_sMAC_default(0); 
    
}
table sMAC_default{
    key= {
        meta.state_default:exact;
    }
    actions = {
            store_state_sMAC_default1;
            NoAction;
    }
     size = 1024;
   default_action =NoAction(); 
    
}
table dMAC_exact{
    key= {
        meta.state_smac:exact;
        hdr.ethernet.dEth:exact;
        
        
    }
    
actions = {
 
          store_state_dMAC;
            drop;
            NoAction;
    }

    size = 1024;
    default_action =NoAction(); 
}

table dMAC_default{
    key= {
        meta.state_smac:exact;
        
    }
    
actions = {
 
          store_state_dMAC_default;
            drop;
            NoAction;
    }

    size = 1024;
    default_action =drop(); 
}
table typEth_exact{
    key= {
        meta.state_dmac:exact;
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

 table typEth_default{
    key= {
        meta.state_dmac:exact;
        
    }
    
actions = {
 
          store_state_typEth_default;
          drop;
            //NoAction;
    }

    size = 1024;
    default_action =drop();//NoAction();
    } 
table proto_exact{
  key={

    meta.state_type:exact;
    //hdr.ipv4.protocol:exact;
    meta.protocol:exact;
  }
  
actions = {
            
            store_state_proto;
            //drop;
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
            
            store_state_proto_default;
            drop;
            //NoAction;
    }

    size = 1024;
    default_action =drop();//NoAction();
}

table sPort_exact{
  key={
    meta.state_proto:exact;
    //hdr.tcp.srcPort:exact;
    //hdr.udp.srcPort:exact;
    meta.sport:exact;
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
table sPort_default{
  key={
    meta.state_proto:exact;
    
  }
  actions = {
    store_state_sPort_default;
    drop;
    //NoAction;
  }
  size = 1024;
  default_action =drop();//NoAction();
}
table dPort_exact{
  key={
    meta.state_sport:exact;
    //hdr.tcp.dstPort:exact;
    //hdr.udp.dstPort:exact;
    meta.dport:exact;
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
table dPort_default{
  key={
    meta.state_sport:exact;
  }
  actions = {
    store_state_dPort_default;
    drop;
    //NoAction;
  }
  size = 1024;
  default_action =drop();///NoAction();
}
table srcIP_exact{
  key={
    meta.state_dport:exact;
    //dr.ipv4.srcAddr:exact;
    //hdr.ipv4.protocol:exact;
    meta.sip:exact;
  }
  actions = {
     //@atomic{
            
            store_state_srcIP;
            //drop;
            NoAction;
             //}
    }

    size = 1024;
    default_action = NoAction();
    //default_action =NoAction(); 
}
table srcIP_default{
  key={
    meta.state_dport:exact;
  }
  actions = {
     //@atomic{
            
            store_state_srcIP_default;
            drop;
           // NoAction;
             //}
    }

    size = 1024;
    default_action = drop();//NoAction();
    //default_action =NoAction(); 
}
table dstIP_exact{
  key={
    meta.state_sip:exact;
    //hdr.ipv4.dstAddr:exact;
    meta.dip:exact;
  }
  
actions = {
            
            store_state_dstIP;
            //drop;
            NoAction;
    }

    size = 1024;
  default_action = NoAction();
  //default_action =NoAction(); 
}
table dstIP_default{
  key={
    meta.state_sip:exact;
  }
  
actions = {
            
            store_state_dstIP_default;
            drop;
            //NoAction;
    }

    size = 1024;
  default_action = drop();//NoAction();
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
            //if(hdr.ethernet.sMAC!=*)
             sMAC_exact.apply();
             if(meta.flag_smac==0){
             sMAC_default.apply();
             }
             
             dMAC_exact.apply();
             //dEth_ternary.apply();
             if(meta.flag_dmac==0){
             dMAC_default.apply();
         	 }
             typEth_exact.apply();
             //typEth_ternary.apply();
             if(meta.flag_type==0){
             typEth_default.apply();
              }

              if (hdr.ipv4.isValid())
              {
                meta.protocol=hdr.ipv4.protocol;
                meta.sip=hdr.ipv4.srcAddr;
                meta.dip=hdr.ipv4.dstAddr;
              }
              if (hdr.ipv6.isValid())
              {
                meta.protocol=hdr.ipv6.protocol;
                meta.sip=hdr.ipv6.srcAddr;
                meta.dip=hdr.ipv6.dstAddr;
              }
              if (hdr.ipv7.isValid())
              {
                meta.protocol=hdr.ipv7.protocol;
                meta.sip=hdr.ipv7.srcAddr;
                meta.dip=hdr.ipv7.dstAddr;
              }
              proto_exact.apply();
            // proto_ternary.apply();
             if(meta.flag_proto==0){
             proto_default.apply();
              }
            
            if(hdr.tcp.isValid()){
              meta.sport= hdr.tcp.srcPort;
              meta.dport= hdr.tcp.dstPort;
            //proto_exact.apply();
          
            }
            if(hdr.udp.isValid()){

            meta.sport= hdr.udp.srcPort;
            meta.dport= hdr.udp.dstPort;
            //proto_exact.apply();
              
            }
             if(hdr.icmp.isValid())
             {
              meta.sport= hdr.icmp.srcPort;
              meta.dport= hdr.icmp.dstPort;
             }
             if(hdr.igmp.isValid())
             {
              meta.sport= hdr.igmp.srcPort;
              meta.dport= hdr.igmp.dstPort;
             }
             if(hdr.ipv6frag.isValid())
             {
              meta.sport= hdr.ipv6frag.srcPort;
              meta.dport= hdr.ipv6frag.dstPort;
             }
             if(hdr.ipv6icmp.isValid())
             {
              meta.sport= hdr.ipv6icmp.srcPort;
              meta.dport= hdr.ipv6icmp.dstPort;
             }
             if(hdr.hoport.isValid())
             {
              meta.sport= hdr.hoport.srcPort;
              meta.dport= hdr.hoport.dstPort;
             }
             sPort_exact.apply();
             //sPort_ternary.apply();
             if(meta.flag_sport==0){
             sPort_default.apply();
	         }
             dPort_exact.apply();
             //dPort_ternary.apply();
             if(meta.flag_dport==0){
             dPort_default.apply();
              }
              srcIP_exact.apply();
            // Source_ternary.apply();
             if(meta.flag_sip==0){
             srcIP_default.apply();
             }
             dstIP_exact.apply();
            // Destination_ternary.apply();
             if(meta.flag_dip==0){
             dstIP_default.apply();
             }
             
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
    apply {//meta.flag_smac=0; 
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
            HashAlgorithm.csum16);
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
        packet.emit(hdr.udp);
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


