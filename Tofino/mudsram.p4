/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

enum bit<16> ether_type_t {

    //ours
    IPV4 = 0x0800,
    EAP  = 0x888E,
    UNKNOWN = 0x0006,
    STUB = 0x0000,

    //extras
    ARP  = 0x0806,
    TPID = 0x8100,
    IPV6 = 0x86DD,
    MPLS = 0x8847
}

enum bit<8> ipv4_proto_t {
    TCP  = 0x06,//6
    UDP  = 0x11,//17,
    ICMP  = 0x01,//1,
    IGMP  = 0x02,//2,
    IPV6frag  = 0x2C,//44,
    IPV6icmp  = 0x3A,//58,
    STUB_PROTO  = 0x63,//99,
    HOPORT  = 0x00
};


const PortId_t CPU_PORT = 64;

/* Table Sizes */
/*
 * We use C preprocessor here so that we can easily overwrite
 * these constants from the command line
 */

/* Table Sizes */
#ifndef LVL1
  #define LVL1 710000
#endif

#ifndef LVL3
  #define LVL3 28
#endif

#ifndef LVL3E
  #define LVL3E 12
#endif

#ifndef LVL4
  #define LVL4 87
#endif

#ifndef LVL6
  #define LVL6 132
#endif

#ifndef LVL6E
  #define LVL6E 37
#endif

#ifndef LVL8
  #define LVL8 432
#endif

#ifndef LVL8E
  #define LVL8E 1
#endif

const int LEVEL1 = LVL1;
const int LEVEL3 = LVL3;
const int LEVEL3E = LVL3E;
const int LEVEL4 = LVL4;
const int LEVEL6 = LVL6;
const int LEVEL6E = LVL6E;
const int LEVEL8 = LVL8;
const int LEVEL8E = LVL8E;


/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t   dst_mac;
    mac_addr_t   src_mac;
    ether_type_t ether_type;
}

//Standard IPv4 Header
header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    ipv4_proto_t    protocol;
    // bit<8>    protocol;
    bit<16>   hdrChecksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

//Standard TCP Header
header tcp_h{

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

//Standard UDP Header
header udp_h{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


struct pair {
    bit<32> tf;
    bit<32> ts;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    tcp_h        tcp;
    udp_h        udp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    //Generic Values
    bit<24> current_state; //contains the current state to match with
    bit<24> stub_current_state_value; //Just for the first level
    bit<8>  flag; //used as a toggle for the match action pipeline

    //used to store port numbers of both UDP and TCP
    bit<16> sport;
    bit<16> dport;
}



    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4:  parse_ipv4;
            ether_type_t.EAP:  parse_ipv4;
            ether_type_t.UNKNOWN:  parse_ipv4;
            ether_type_t.STUB:  parse_ipv4;
            default: accept;
        }
    }


    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol) {
            ipv4_proto_t.TCP:  parse_tcp;
            ipv4_proto_t.ICMP:  parse_tcp;
            ipv4_proto_t.IGMP:  parse_tcp;
            ipv4_proto_t.IPV6frag:  parse_tcp;
            ipv4_proto_t.IPV6icmp:  parse_tcp;
            ipv4_proto_t.HOPORT:  parse_tcp;
            ipv4_proto_t.STUB_PROTO:  parse_tcp;
            ipv4_proto_t.UDP:  parse_udp;
            default: accept;
        }

    }

    //Parse the TCP Header
    state parse_tcp {
       pkt.extract(hdr.tcp);
       transition accept;
    }

    //Parse the UDP Header
    state parse_udp {
       pkt.extract(hdr.udp);
       transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{


    //REGISTERS

    Register<pair, bit<32>>(1, {0,0}) tst_ing;

    RegisterAction<pair, bit<32>, bit<32>>(tst_ing) tst_action = {
        void apply(inout pair ig_tst) {
            ig_tst.tf = (bit <32>)ig_prsr_md.global_tstamp[47:32];
            ig_tst.ts = ig_prsr_md.global_tstamp[31:0];
        }
    };

    Register<bit<32>, bit<32>>(1, 32w0) tst_ingg;

    RegisterAction<bit<32>, bit<32>, bit<32>>(tst_ingg) tst_actionn = {
        void apply(inout bit<32> ig_tst) {
            ig_tst = ig_prsr_md.global_tstamp[31:0];
        }
    };

    //Send the packet normally
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    //Drop the packet
    action drop() {
        //Packet Drop Primitive
        ig_dprsr_md.drop_ctl = 1;
    }


    //***LEVEL 1 Special Action
    action default_action_one(bit<24> current_state)
    {
        // Just store a stub state value
        meta.stub_current_state_value = current_state;
    }

    //***Generic match actions LEVELS(2-7)
    //exact table match
    action ns_exact(bit<24> next_state)
    {
      meta.flag = 1;
      meta.current_state = next_state;
    }
    //default table match
    action ns_default(bit<24> next_state)
    {
    	meta.flag = 0;
    	meta.current_state = next_state;
    }


    action ns_exact_last(PortId_t switchPort)
    {
        //Forward action
        meta.flag = 1;
        send(148);
            // ig_tm_md.ucast_egress_port = switchPort;

    }
    //default table match
    action ns_default_last(PortId_t switchPort)
    {
    	//Forward action
        meta.flag = 0;
        send(148);
    }


    //****************TABLES*****************//
    table sMAC_exact{
        key= {
            hdr.ethernet.src_mac:exact;
        }
        actions = {
                ns_exact;
                drop;
        }
        size = LEVEL1;
        default_action = drop;
    }

    //**LEVEL 2**//
    table typEth_exact{
        key= {
            meta.current_state:exact;
            hdr.ethernet.ether_type:exact;
        }
        actions = {
              ns_exact;
              NoAction;
        }
        size = LEVEL3;
        default_action = NoAction();
    }
    table typEth_default{
        key= {
            meta.current_state:exact;
        }
        actions = {
              ns_default;
              drop;
        }
        size = LEVEL3E;
        default_action =drop();
    }

    //**LEVEL 3**//
    table protocol_exact{
        key= {
            meta.current_state:exact;
            hdr.ipv4.protocol:exact;
        }
        actions = {
              ns_exact;
              drop;
        }
        size = LEVEL4;
        default_action = drop();
    }

    //**LEVEL 6**//
    table dPort_exact{
        key= {
            meta.current_state:exact;
            meta.dport:exact;
        }
        actions = {
              ns_exact;
              NoAction;
        }
        size = LEVEL6;
        default_action = NoAction();
    }
    table dPort_default{
        key= {
            meta.current_state:exact;
        }
        actions = {
              ns_default;
              drop;
        }
        size = LEVEL6E;
        default_action =drop();
    }

    //**LEVEL 8**//
    table dstIP_exact{
        key= {
            meta.current_state:exact;
            hdr.ipv4.dst_addr:exact;
        }
        actions = {
              ns_exact_last;
              NoAction;
        }
        size = LEVEL8;
        default_action = NoAction();
    }

    table dstIP_default{
        key= {
            meta.current_state:exact;
        }
        actions = {
              ns_default_last;
              drop;
        }
        size = LEVEL8E;
        default_action = drop();
    }


    apply {

        tst_action.execute(0);
        tst_actionn.execute(0);

        if (hdr.tcp.isValid()){
            meta.sport= hdr.tcp.srcPort;
            meta.dport= hdr.tcp.dstPort;
        }
        else if (hdr.udp.isValid()){
            meta.sport= hdr.udp.srcPort;
            meta.dport= hdr.udp.dstPort;
        }


        sMAC_exact.apply();
        meta.flag = 0;

        typEth_exact.apply();
        if(meta.flag==0){
            typEth_default.apply();
        }
        meta.flag = 0;

        protocol_exact.apply();
        meta.flag = 0;

        dPort_exact.apply();
        if(meta.flag==0){
            dPort_default.apply();
        }
        meta.flag = 0;

        dstIP_exact.apply();
        if(meta.flag==0){
            dstIP_default.apply();
        }



        // if (hdr.ipv4.isValid()) {
        //
        //     if (ipv4_host.apply().miss) {
        //         ipv4_lpm.apply();
        //     }
        // }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
        ethernet_h   ethernet;
        ipv4_h       ipv4;
        tcp_h        tcp;
        udp_h        udp;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }



}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{

    Register<pair, bit<32>>(1, {0,0}) tst_ing;

    RegisterAction<pair, bit<32>, bit<32>>(tst_ing) tst_action = {
        void apply(inout pair ig_tst) {
            ig_tst.tf = (bit <32>)eg_prsr_md.global_tstamp[47:32];
            ig_tst.ts = eg_prsr_md.global_tstamp[31:0];
        }
    };

    Register<bit<32>, bit<32>>(1, 32w0) tst_ingg;

    RegisterAction<bit<32>, bit<32>, bit<32>>(tst_ingg) tst_actionn = {
        void apply(inout bit<32> ig_tst) {
            ig_tst = eg_prsr_md.global_tstamp[31:0];
        }
    };


    apply {

        tst_action.execute(0);
        tst_actionn.execute(0);

    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
