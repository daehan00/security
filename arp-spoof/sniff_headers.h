#include <pcap.h>
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_short uh_sport;  /* source port */
    u_short uh_dport;  /* destination port */
    u_short uh_len;    /* length */
    u_short uh_sum;    /* checksum */
};

/* ICMP header */
struct sniff_icmp {
    u_char type;       /* ICMP type */
    u_char code;       /* ICMP code */
    u_short checksum;  /* checksum */
    u_short id;        /* identifier */
    u_short seq;       /* sequence number */
};

/* ARP header */
struct sniff_arp {
    u_short htype;     /* hardware type */
    u_short ptype;     /* protocol type */
    u_char hlen;       /* hardware address length */
    u_char plen;       /* protocol address length */
    u_short oper;      /* operation (request or reply) */
    u_char sha[6];     /* sender hardware address (MAC) */
    u_char spa[4];     /* sender protocol address (IP) */
    u_char tha[6];     /* target hardware address */
    u_char tpa[4];     /* target protocol address */
};


/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
#define SIZE_IP_MINIMUM 20
#define SIZE_IP_MAXIMUM 60

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

#define MACADDRSTRLEN 18;
