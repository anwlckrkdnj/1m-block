#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <set>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <string>
#include <libnetfilter_queue/libnetfilter_queue.h>
using namespace std;

#define HTTP 80

set<string> siteset;

char target_web[256];

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

uint32_t check_filter(unsigned char* data, int ret) {
        struct libnet_ipv4_hdr* ipv4_hdr = (libnet_ipv4_hdr*)(data);

        if(ipv4_hdr->ip_p != IPPROTO_TCP)
                return NF_ACCEPT;

        int ip_hdr_len = ipv4_hdr->ip_hl << 2;
        int packet_len = ipv4_hdr->ip_len;

        struct libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)(data + ip_hdr_len);

	if(ntohs(tcp_hdr->th_dport) != HTTP)
		return NF_ACCEPT;

	int tcp_hdr_len = tcp_hdr->th_off << 2;

	int payload_len = packet_len - ip_hdr_len - tcp_hdr_len;

	if(payload_len == 0)
		return NF_ACCEPT;

	char* payload = (char*)(data + ip_hdr_len + tcp_hdr_len);
	char* target = "Host: ";

	char tmp[32];

	payload = strstr(payload, target);
	while(payload != NULL) {
		payload += strlen(target);
		memset(tmp, 0, 32);

		for(int i = 0 ; ; i++) {
			if(payload[i] == '\r')
				break;
			tmp[i] = payload[i];
		}
		
		string str(tmp);

		if(siteset.find(str) != siteset.end()) {
			cout << "blocked " << str << '\n';
			return NF_DROP;
		}
		payload = strstr(payload, target);
	}	

        return NF_ACCEPT;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, uint32_t* verdict)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ",
		//	ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);
		/*
		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
		*/
	}

	mark = nfq_get_nfmark(tb);
	if (mark) {
		//printf("mark=%u ", mark);
	}

	ifi = nfq_get_indev(tb);
	if (ifi) {
		//printf("indev=%u ", ifi);
	}

	ifi = nfq_get_outdev(tb);
	if (ifi) {
		//printf("outdev=%u ", ifi);
	}
	ifi = nfq_get_physindev(tb);
	if (ifi) {
		//printf("physindev=%u ", ifi);
	}

	ifi = nfq_get_physoutdev(tb);
	if (ifi) {
		//printf("physoutdev=%u ", ifi);
	}

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		//printf("payload_len=%d ", ret);
		*verdict = check_filter(data, ret);
		//dump(data, ret);
	}

	//fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t verdict;
	u_int32_t id = print_pkt(nfa, &verdict);
	//printf("entering callback\n");
	return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

void usage() {
        printf("1m-block <site list>\n");
        printf("sample : 1m-block sitelist.txt\n");
}

int main(int argc, char **argv)
{
	if(argc != 2) {
		usage();
		return -1;
	}

	ifstream sitelist;
    	sitelist.open(argv[1]);

	if(!sitelist.is_open()) {
		printf("cant open file\n");
		return -1;
	}

	string str;
	while(!sitelist.eof()) {
		sitelist >> str;
		siteset.insert(str);
	}

	sitelist.close();

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
