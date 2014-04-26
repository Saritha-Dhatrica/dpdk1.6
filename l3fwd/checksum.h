extern uint16_t htons (uint16_t __hostshort)
	__THROW __attribute__ ((__const__));
extern uint16_t ntohs (uint16_t __netshort)
	__THROW __attribute__ ((__const__));

struct pseudo_iphdr {
	uint8_t  src_addr[16]; /**< IP address of source host. */
	uint8_t  dst_addr[16]; /**< IP address of destination host. */ 
	uint16_t payload_len;  /**< IP payload length. */
	uint16_t vtc_flow;     /**< IP version, traffic class & flow label. */
	uint8_t  hop_limits;   /**< Hop limits. */
	uint8_t  proto;        /**< Protocol, next header. */
};

struct tcp_header {
	uint16_t sport; /**< TCP source port. */ 
	uint16_t dport; /**< TCP destiantion port. */
	uint32_t seq;   /**< TCP sequence number. */
	uint32_t ack;   /**< TCP acknowledgement number. */
	uint8_t off;    /**< TCP data offset. */
	uint8_t flags;  /**< TCP flags. */
	uint16_t win;   /**< TCP window size. */
	uint16_t csum;  /**< TCP checksum. */
	uint16_t urp;   /**< TCP urgent pointer. */
};

struct udp_header {
	uint16_t sport; /**< UDP source port. */
	uint16_t dport; /**< UDP destiantion port. */
	uint16_t len;   /**< UDP lenght. */  
	uint16_t csum;  /**< UDP checksum. */
};

static inline
uint16_t checksum(uint32_t sum, const void *data, int nr_bytes)
{
	const uint16_t* p = (const uint16_t*)data;
	while (nr_bytes > 1) {
		sum += *p++;
		nr_bytes -= 2;
	}

	if (nr_bytes){
//		sum += htons(*(uint8_t*)p << 8);
	}

	sum = (sum >> 16) + (sum & 0xffff);  // add high 16 to low 16.
	sum += (sum >> 16);                  // add carry bit.
	return ~sum;
}

/* 
* Name : compute_checksum
* Desciption : Computes TCP/UDP checksum depending on the ip->proto field.
* Params :
*	ipv6_hdr - pointer to the ipv6_hdr
*	hdr      - Transport header(TCP/UDP)
* Returns : None	    	
*/
static inline
void compute_checksum(struct ipv6_hdr *ip, void *hdr)
{
	uint16_t *p;
	uint32_t sum;
	int bytes;
	struct pseudo_iphdr pip;
	pip.payload_len = (ip->payload_len);
	pip.proto = (ip->proto);
	/* Not requried for checksum calculation. */
	pip.vtc_flow = 0;
	pip.hop_limits = 0;

	for (bytes =0; bytes<16; bytes++) {
		pip.src_addr[bytes] = (ip->src_addr[bytes]);
		pip.dst_addr[bytes] = (ip->dst_addr[bytes]);
	}

	p = (uint16_t*)&pip;

	for (bytes =0; bytes< 20; bytes++) {
		sum += p[bytes];
	}

	if (ip->proto == IPPROTO_UDP)
	{
		struct udp_header *udp = (struct udp_header *)hdr;
		udp->csum = 0;
		udp->csum = checksum(sum, udp, ntohs(ip->payload_len));
	}
	else
	{
		struct tcp_header *tcp = (struct tcp_header *)hdr;
		tcp->csum = 0;
		tcp->csum = checksum(sum, tcp, ntohs(ip->payload_len));
	}
}
