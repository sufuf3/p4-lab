/* INT shim header for TCP/UDP */
header intl4_shim_t {
    bit<8> int_type;
    bit<8> rsvd1;
    bit<8> len;
    bit<8> rsvd2;
}
/* INT tail header for TCP/UDP */
header intl4_tail_t {
    bit<8> next_proto;
    bit<16> dest_port;
    bit<8> dscp;
}
/* INT headers */
header int_header_t {
    bit<2> ver;
    bit<2> rep;
    bit<1> c;
    bit<1> e;
    bit<5> rsvd1;
    bit<5> ins_cnt;
    bit<8> max_hop_cnt;
    bit<8> total_hop_cnt;
    bit<4> instruction_mask_0003; /* split the bits for lookup */
    bit<4> instruction_mask_0407;
    bit<4> instruction_mask_0811;
    bit<4> instruction_mask_1215;
    bit<16> rsvd2;
}
/* INT meta-value headers - different header for each value type */
header int_switch_id_t {
    bit<32> switch_id;
}

header int_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}
header int_hop_latency_t {
    bit<32> hop_latency;
}
header int_q_occupancy_t {
    bit<8> q_id;
    bit<24> q_occupancy;
}
header int_ingress_tstamp_t {
    bit<32> ingress_tstamp;
}
header int_egress_tstamp_t {
    bit<32> egress_tstamp;
}
header int_q_congestion_t {
    bit<8> q_id;
    bit<24> q_congestion;
}
header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}
/* standard ethernet/ip/tcp headers */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
/* define diffserv field as DSCP(6b) + ECN(2b) */
header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    intl4_shim_t intl4_shim;
    int_header_t int_header;
    int_switch_id_t int_switch_id;
    int_port_ids_t int_port_ids;
    int_hop_latency_t int_hop_latency;
    int_q_occupancy_t int_q_occupancy;
    int_ingress_tstamp_t int_ingress_tstamp;
    int_egress_tstamp_t int_egress_tstamp;
    int_q_congestion_t int_q_congestion;
    int_egress_port_tx_util_t int_egress_port_tx_util;
}
/* switch internal variables for INT logic implementation */
struct int_metadata_t {
    bit<16> insert_byte_cnt;
    bit<8> int_hdr_word_len;
    bit<32> switch_id;
}
struct metadata {
    int_metadata_t int_metadata;
}
