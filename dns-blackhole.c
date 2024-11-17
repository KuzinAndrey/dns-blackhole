/*
DNS blackhole server for resolve list of domain names to blackhole IP.
Can be used to block some ads, malware, pop-ups sites or similar tasks.
Author: Kuzin Andrey <kuzinandrey@yandex.ru>
License: MIT
Vcs: https://github.com/KuzinAndrey/dns-blackhole

History:
	2024-11-06 - Start of development
	2024-11-08 - Dive into libevent universe
	2024-11-16 - First production ready DNS part on UDP
	2024-11-17 - Add support HTTP & HTTPS blackhole, DNS on TCP,
	             some statistics, first public commit
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>

#include <event2/event-config.h>
#include <sys/types.h>

#ifdef EVENT__HAVE_UNISTD_H
#include <unistd.h>
#endif

// #ifdef _WIN32
// #include <winsock2.h>
// #include <ws2tcpip.h>
// #include <getopt.h>
// #else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
// #endif

#define OPENSSL_NO_DEPRECATED_3_0
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <evhttp.h>
#include <event2/bufferevent_ssl.h>
#include <event2/thread.h>
#include <event2/event.h>
#include "event2/listener.h"
#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/dns_compat.h>
#include <event2/util.h>

#define W(...) evbuffer_add_printf(buf, __VA_ARGS__)

#define __TRACE__ fprintf(stderr,"%s %s:%d\n", __func__, __FILE__, __LINE__);

#define DEBUG(...) do { if (opt_debug) { fprintf(stderr, __VA_ARGS__); fprintf(stderr," %s:%d\n", __FILE__, __LINE__); } } while(0);

static struct event_base *event_main_base = NULL;

static int opt_debug = 0;
static int opt_timeout_upstream = 10000;
static char *opt_file_name = NULL;
static int opt_blackhole_ip4_set = 0;
static int opt_blackhole_ip6_set = 0;
static struct in_addr opt_blackhole_ip4 = {0};
static struct in6_addr opt_blackhole_ip6 = {0};
static int opt_blackhole_server = 0;
// static int opt_api_port = 0; // TODO

#ifdef EVENT__HAVE_OPENSSL
static char *opt_https_key_file = NULL;
static char *opt_https_cert_file = NULL;
#endif

#define PROGRAM_VERSION "v0.1"

// DOMAIN NAMES HASH TABLE
////////////////////////////////////////////

// Structure for hash table entry
struct str_hash {
	const char *str;
	uint32_t hit;
	struct str_hash *next;
};

// Global hash table
static size_t hash_table_size = 0xFFFF;
static struct str_hash **htable = NULL;
static char *htable_data = NULL;
static long htable_data_size = 0;
static size_t line_count = 0;
static size_t htable_inserted_count = 0;
static size_t htable_skipped_count = 0;

// Calc hash for string
static unsigned int
calc_str_hash(const char *s) {
	unsigned int h = 0;
	if (!s) return 0;
	while (*s) {
		h = (h << 5) - h + tolower(*s);
		h %= hash_table_size;
		s++;
	}
	return h;
}

// Insert string pointer in hash table
static int
insert_str_hash(struct str_hash *ht[], const char *s) {
	unsigned int i = calc_str_hash(s);
	struct str_hash *n = calloc(1, sizeof(struct str_hash));
	if (!n) return -1;
	n->str = s;
	n->next = ht[i];
	ht[i] = n;
	return 0;
}

// Find string in hash table
static struct str_hash *
find_str_hash(struct str_hash *ht[], const char *s) {
	unsigned int i = calc_str_hash(s);
	struct str_hash *n = ht[i];
	while (n) {
		if (!strcasecmp(n->str, s)) return n;
		n = n->next;
	}
	return NULL;
}

// Test domain for blocking
static struct str_hash *
domain_is_blocked(struct str_hash *ht[], const char *name) {
	char buf[256]; // rfc3986 max domain len can't be more than 255 bytes
	int len = strlen(name);
	struct str_hash *r;

	if (len != snprintf(buf, sizeof(buf), "%s", name)) return NULL;

	// check full name
	r = find_str_hash(ht, buf);
	if (r) return r;

	// check all parent domains for blocking
	for (int i = len; i >= 0; i--) {
		if (buf[i] == '.') {
			buf[i] = 0;
			r = find_str_hash(ht, &buf[i+1]);
			if (r) return r;
			buf[i] = '.';
		}
	}

	return NULL;
}

// Clean hash table from strings
static void
clean_str_hash(struct str_hash *ht[]) {
	for (size_t i = 0; i < hash_table_size; ++i) {
		while (ht[i]) {
			struct str_hash *d = ht[i]->next;
			free(ht[i]);
			ht[i] = d;
		}
	}
}

// DNS SERVER AND RESOLVER
////////////////////////////

#define DNS_PORT 53 // DNS port

static int blackhole_ttl = 10;

static struct event *sig_int = NULL;
static struct event *sig_term = NULL;
static struct event *sig_quit = NULL;
static struct event *sig_hup = NULL;

static struct event_base *event_server_base = NULL;
static struct evdns_base *evdns_server_base = NULL;

static struct event_base *event_resolver_base = NULL;
static struct evdns_base *evdns_resolver_base = NULL;

struct resolver_result {
	int resolved;
	char type;
	int ttl;
	int rr_count;
	union {
		ev_uint32_t *a;
		struct in6_addr *aaaa;
		char *ptr_name;
		void *raw;
		struct evdns_reply_ns *ns;
		struct evdns_reply_mx *mx;
		struct evdns_reply_soa *soa;
		struct evdns_reply_txt *txt;
	} data;
	char *cname;
};

static struct statistics {
	uint64_t requests;
	uint64_t resolves;
	uint64_t blocked;
	uint64_t type_a;
	uint64_t type_ptr;
	uint64_t type_aaaa;
	uint64_t type_cname;
	uint64_t type_ns;
	uint64_t type_mx;
	uint64_t type_soa;
	uint64_t type_txt;
	uint64_t type_soa_auth;
	uint64_t type_unknown;
} stat;

static void
resolver_callback(int result, char type, int count, int ttl, void *addrs, void *data) {
	struct resolver_result *r = data;
	char buf[INET6_ADDRSTRLEN+1];
	const char *s;
	int i, j;

	r->rr_count = 0;
	r->ttl = ttl;
	stat.resolves++;

	if (!addrs && !count) {
		r->resolved = 1;
		return;
	}

	switch (type) {
	case DNS_IPv4_A: // 1
		DEBUG(" -- resolved A: %d rec (ttl = %d)", count, ttl);
		r->data.a = calloc(count, sizeof(r->data.a[0]));
		if (!r->data.a) break;
		memcpy(r->data.a, addrs, count * sizeof(r->data.a[0]));
		for (i = 0; i < count; ++i) {
			s = evutil_inet_ntop(AF_INET, &r->data.a[i], buf, sizeof(buf));
			if (s) DEBUG("\t%d: %s", i, s);
		}
		r->rr_count = count;
		stat.type_a++;
		break;

	case DNS_PTR: // 2
		r->data.ptr_name = strdup(addrs);
		if (!r->data.ptr_name) break;
		DEBUG("PTR: %s", r->data.ptr_name);
		r->rr_count = 1;
		stat.type_ptr++;
		break;

	case DNS_IPv6_AAAA: // 3
		DEBUG(" -- resolved AAAA: %d rec (ttl = %d)", count, ttl);
		r->data.aaaa = calloc(count, sizeof(r->data.aaaa[0]));
		if (!r->data.aaaa) break;
		memcpy(r->data.aaaa, addrs, count * sizeof(r->data.aaaa[0]));
		for (i = 0; i < count; ++i) {
			s = evutil_inet_ntop(AF_INET6, &r->data.aaaa[i], buf, sizeof(buf));
			if (s) DEBUG("\t%d: %s", i, s);
		}
		r->rr_count = count;
		stat.type_aaaa++;
		break;

	case DNS_CNAME: // 4
		r->cname = strdup((char*)addrs);
		if (!r->cname) break;
		DEBUG(" -- resolved CNAME: %s (ttl = %d)", r->cname, ttl);
		// r->rr_count = 1;
		stat.type_cname++;
		break;

	case DNS_NS: // 5
		struct evdns_reply_ns *ns = addrs;
		r->data.ns = calloc(count, sizeof(r->data.ns[0]));
		if (!r->data.ns) break;
		DEBUG(" -- resolved NS: %d rec (ttl = %d)", count, ttl);
		for (i = 0; i < count; ++i) {
			r->data.ns[r->rr_count].name = strdup(ns[i].name);
			if (!r->data.ns[r->rr_count].name) continue;
			DEBUG("\t%d: %s", i, r->data.ns[r->rr_count].name);
			r->rr_count++;
		}
		stat.type_ns++;
		break;

	case DNS_MX: // 6
		struct evdns_reply_mx *mx = addrs;
		r->data.mx = calloc(count, sizeof(r->data.mx[0]));
		if (!r->data.mx) break;
		DEBUG(" -- resolved MX: %d rec (ttl = %d)", count, ttl);
		for (i = 0; i < count; ++i) {
			memcpy(&r->data.mx[r->rr_count], &mx[i], sizeof(mx[i]));
			r->data.mx[r->rr_count].name = strdup(mx[i].name);
			if (!r->data.mx[r->rr_count].name) continue;
			DEBUG("\t%d: %s", i, r->data.mx[r->rr_count].name);
			r->rr_count++;
		}
		stat.type_mx++;
		break;

	case DNS_SOA: // 7
	case DNS_SOA_AUTH: // 9
		struct evdns_reply_soa *soa = addrs;
		r->data.soa = calloc(count, sizeof(r->data.soa[0]));
		if (!r->data.soa) break;
		DEBUG(" -- resolved %s: %d rec (ttl = %d)",
			(type == DNS_SOA ? "SOA":"SOA_AUTH"), count, ttl);
		for (i = 0; i < count; ++i) {
			memcpy(&r->data.soa[r->rr_count], &soa[i], sizeof(soa[i]));
			r->data.soa[r->rr_count].nsname = strdup(soa[i].nsname);
			if (!r->data.soa[r->rr_count].nsname) continue;
			r->data.soa[r->rr_count].email = strdup(soa[i].email);
			if (!r->data.soa[r->rr_count].email) {
				free(r->data.soa[r->rr_count].nsname);
				continue;
			}
			DEBUG("\t%d: %s %s", i, r->data.soa[r->rr_count].nsname,
				r->data.soa[r->rr_count].email);
			r->rr_count++;
		}
		if (type == DNS_SOA) stat.type_soa++;
		if (type == DNS_SOA_AUTH) stat.type_soa_auth++;
		break;

	case DNS_TXT: // 8
		struct evdns_reply_txt *txt = addrs;
		r->data.txt = calloc(count, sizeof(r->data.txt[0]));
		if (!r->data.txt) break;
		DEBUG(" -- resolved TXT: %d rec (ttl = %d)", count, ttl);
		for (i = 0; i < count; ++i) {
			size_t total_len = 0, len; char *p = txt[i].text;
			for (j = 0; j < txt[i].parts; j++) {
				len = strlen(p) + 1;
				total_len += len;
				p += len;
			}
			r->data.txt[r->rr_count].parts = txt[i].parts;
			r->data.txt[r->rr_count].text = calloc(1, total_len);
			if (!r->data.txt[r->rr_count].text) continue;
			memcpy(r->data.txt[r->rr_count].text, txt[i].text, total_len);
			DEBUG("\t%d: %s", i, r->data.txt[r->rr_count].text);
			r->rr_count++;
		}
		stat.type_txt++;
		break;

	default:
		DEBUG(" -- UNKNOWN resolver callback type: %d (ttl = %d)", type, ttl);
		stat.type_unknown++;
		break;
	} // switch

	r->resolved = (type == r->type);

	/*
	 * type of answer not match with request, but receive DNS_SOA_AUTH
	 * this mean error was, make it resolved with type SOA_AUTH
	 */
	if (!r->resolved && type == DNS_SOA_AUTH && result != 0) {
		DEBUG(" -- get soa_auth with err=%d (%s)", result, evdns_err_to_string(result));
		r->type = DNS_SOA_AUTH;
		r->resolved = 1;
	}

} // resolver_callback()

#define SEND_SOA_AUTH_IF_PRESENT \
	} else if (myreq.type == DNS_SOA_AUTH && myreq.data.soa) { \
	DEBUG(" -- send %s for %s...", "SOA_AUTH", req->questions[i]->name); \
	DEBUG("\t%s, %s = %d", myreq.data.soa->nsname, myreq.data.soa->email, myreq.data.soa->serial); \
	r = evdns_server_request_add_soa_reply(req, req->questions[i]->name, \
		myreq.data.soa, 1, myreq.ttl); \
	if (r < 0) DEBUG("err %d", r); \
	free(myreq.data.soa->nsname); \
	free(myreq.data.soa->email); \
	free(myreq.data.soa);

static void
server_callback(struct evdns_server_request *req, void *data)
{
	int i, j, r;
	int waitreq;
	struct resolver_result myreq;
	struct str_hash *hash;
	(void)data;

	memset(&myreq, 0, sizeof(struct resolver_result));
	stat.requests++;

	for (i = 0; i < req->nquestions; ++i) {

		if (req->questions[i]->dns_question_class != EVDNS_CLASS_INET) {
			DEBUG(" -- Unknown class %d", req->questions[i]->dns_question_class);
			continue;
		}

		switch (req->questions[i]->type) {

		case EVDNS_TYPE_A: // 1
			hash = domain_is_blocked(htable, req->questions[i]->name);
			if (hash) {
				DEBUG(" -- Send blackhole %s IP for %s", "A", req->questions[i]->name);
				r = evdns_server_request_add_a_reply(req,
					req->questions[i]->name, 1, &opt_blackhole_ip4, blackhole_ttl);
				if (r < 0) DEBUG("err %d", r);
				stat.blocked++;
				hash->hit++;
				break;
			}
			DEBUG(" -- Try resolve %s for %s", "A", req->questions[i]->name);
			myreq.type = DNS_IPv4_A;
			evdns_base_resolve_ipv4(evdns_resolver_base, req->questions[i]->name,
				DNS_CNAME_CALLBACK, resolver_callback, &myreq);
			waitreq = opt_timeout_upstream;
			while (waitreq > 0) {
				if (!myreq.resolved) { usleep(1000); waitreq--; continue; }
				if (myreq.type == DNS_IPv4_A && myreq.data.a) {
					if (myreq.cname) {
						DEBUG(" -- send CNAME %s for %s...", myreq.cname, req->questions[i]->name);
						r = evdns_server_request_add_cname_reply(req, req->questions[i]->name,
							myreq.cname, myreq.ttl);
						if (r < 0) DEBUG("err %d", r);
						free(myreq.cname);
					}
					DEBUG(" -- send %d %s for %s...", myreq.rr_count, "IPv4", req->questions[i]->name);
					for (j = 0; j < myreq.rr_count; ++j) {
						r = evdns_server_request_add_a_reply(req,
							req->questions[i]->name, 1, &myreq.data.a[j], myreq.ttl);
						if (r < 0) DEBUG("err %d", r);
					}
					free(myreq.data.a);
					SEND_SOA_AUTH_IF_PRESENT
				} else DEBUG("!?? %d", myreq.type);
				break;
			}
			if (waitreq == 0) DEBUG(" -- %s timeout for %s", "A", req->questions[i]->name);
			break;

		case EVDNS_TYPE_NS: // 2
			DEBUG(" -- Try resolve %s for %s", "NS", req->questions[i]->name);
			myreq.type = DNS_NS;
			evdns_base_resolve_ns(evdns_resolver_base, req->questions[i]->name, 0, resolver_callback, &myreq);
			waitreq = opt_timeout_upstream;
			while (waitreq > 0) {
				if (!myreq.resolved) { usleep(1000); waitreq--; continue; }
				if (myreq.type == DNS_NS && myreq.data.ns) {
					DEBUG(" -- send %d %s for %s...", myreq.rr_count, "NS", req->questions[i]->name);
					for (j = 0; j < myreq.rr_count; ++j) {
						DEBUG("\t%d: %s", j, myreq.data.ns[j].name);
						r = evdns_server_request_add_ns_reply(req,
							req->questions[i]->name,
							myreq.data.ns[j].name, myreq.ttl);
						if (r < 0) DEBUG("err %d", r);
						free(myreq.data.ns[j].name);
					}
					free(myreq.data.ns);
					SEND_SOA_AUTH_IF_PRESENT
				} else DEBUG("!?? %d", myreq.type);
				break;
			}
			if (waitreq == 0) DEBUG(" -- %s timeout for %s", "NS", req->questions[i]->name);
			break;

		case EVDNS_TYPE_CNAME: // 5
			DEBUG(" -- Try resolve %s for %s", "CNAME", req->questions[i]->name);
			myreq.type = DNS_CNAME;
			evdns_base_resolve_cname(evdns_resolver_base, req->questions[i]->name, 0, resolver_callback, &myreq);
			waitreq = opt_timeout_upstream;
			while (waitreq > 0) {
				if (!myreq.resolved) { usleep(1000); waitreq--; continue; }
				DEBUG("type = %d, cname = %s", myreq.type, myreq.cname ? myreq.cname : "NULL");
				if (myreq.type == DNS_CNAME && myreq.cname) {
					DEBUG(" -- send %d %s for %s...", myreq.rr_count, "CNAME", req->questions[i]->name);
					r = evdns_server_request_add_cname_reply(req, req->questions[i]->name,
						myreq.cname, myreq.ttl);
					if (r < 0) DEBUG("err %d", r);
					free(myreq.cname);
					SEND_SOA_AUTH_IF_PRESENT
				} else DEBUG("!?? %d", myreq.type);
				break;
			}
			if (waitreq == 0) DEBUG(" -- %s timeout for %s", "CNAME", req->questions[i]->name);
			break;

		case EVDNS_TYPE_SOA: // 6
			DEBUG(" -- Try resolve %s for %s", "SOA", req->questions[i]->name);
			myreq.type = DNS_SOA;
			evdns_base_resolve_soa(evdns_resolver_base, req->questions[i]->name, 0, resolver_callback, &myreq);
			waitreq = opt_timeout_upstream;
			while (waitreq > 0) {
				if (!myreq.resolved) { usleep(1000); waitreq--; continue; }
				if (myreq.type == DNS_SOA && myreq.data.soa) {
					DEBUG(" -- send %s for %s...", "SOA", req->questions[i]->name);
					DEBUG("\t%s, %s = %d", myreq.data.soa->nsname, myreq.data.soa->email, myreq.data.soa->serial);
					r = evdns_server_request_add_soa_reply(req, req->questions[i]->name,
						myreq.data.soa, 0, myreq.ttl);
					if (r < 0) DEBUG("err %d", r);
					free(myreq.data.soa->nsname);
					free(myreq.data.soa->email);
					free(myreq.data.soa);
					SEND_SOA_AUTH_IF_PRESENT
				} else DEBUG("!?? %d", myreq.type);
				break;
			}
			if (waitreq == 0) DEBUG(" -- %s timeout for %s", "SOA", req->questions[i]->name);
			break;

		case EVDNS_TYPE_PTR: // 12
			struct in_addr ptr_ip;
			char addr[255];
			int len = sprintf(addr, "%s", req->questions[i]->name);
			if (!strcmp(addr + len - 13, ".in-addr.arpa")) {
				addr[len - 13] = '\0';
				if (!inet_aton(addr, &ptr_ip)) {
					DEBUG("can't %s inet_aton", addr);
					break;
				} else ptr_ip.s_addr = ntohl(ptr_ip.s_addr);
			} else {
				if (!inet_aton(addr, &ptr_ip)) {
					DEBUG("can't %s inet_aton", addr);
					break;
				}
			}
			DEBUG(" -- Try resolve %s for %s", "PTR", req->questions[i]->name);
			myreq.type = DNS_PTR;
			evdns_base_resolve_reverse(evdns_resolver_base, &ptr_ip, 0, resolver_callback, &myreq);
			waitreq = opt_timeout_upstream;
			while (waitreq > 0) {
				if (!myreq.resolved) { usleep(1000); waitreq--; continue; }
				if (myreq.type == DNS_PTR && myreq.data.ptr_name) {
					DEBUG(" -- send %d %s for %s...", myreq.rr_count, "PTR", req->questions[i]->name);
					DEBUG("\tptr: %s", myreq.data.ptr_name);
					r = evdns_server_request_add_ptr_reply(req, NULL, req->questions[i]->name,
						myreq.data.ptr_name, myreq.ttl);
					if (r < 0) DEBUG("err %d", r);
					free(myreq.data.ptr_name);
				} else DEBUG("!?? %d", myreq.type);
				break;
			}
			if (waitreq == 0) DEBUG(" -- %s timeout for %s", "PTR", req->questions[i]->name);
			break;

		case EVDNS_TYPE_MX: // 15
			DEBUG(" -- Try resolve %s for %s", "MX", req->questions[i]->name);
			myreq.type = DNS_MX;
			evdns_base_resolve_mx(evdns_resolver_base, req->questions[i]->name,
				0, resolver_callback, &myreq);
			waitreq = opt_timeout_upstream;
			while (waitreq > 0) {
				if (!myreq.resolved) { usleep(1000); waitreq--; continue; }
				if (myreq.type == DNS_MX && myreq.data.mx) {
					DEBUG(" -- send %d %s for %s...", myreq.rr_count, "MX", req->questions[i]->name);
					for (j = 0; j < myreq.rr_count; ++j) {
						DEBUG("\t%d: %s = %d", j, myreq.data.mx[j].name, myreq.data.mx[j].pref);
						r = evdns_server_request_add_mx_reply(req, req->questions[i]->name,
							&myreq.data.mx[j], myreq.ttl);
						if (r < 0) DEBUG("err %d", r);
						free(myreq.data.mx[j].name);
					}
					free(myreq.data.mx);
					SEND_SOA_AUTH_IF_PRESENT
				} else DEBUG("!?? %d", myreq.type);
				break;
			}
			if (waitreq == 0) DEBUG(" -- %s timeout for %s", "MX", req->questions[i]->name);
			break;

		case EVDNS_TYPE_TXT: // 16
			DEBUG(" -- Try resolve %s for %s", "TXT", req->questions[i]->name);
			myreq.type = DNS_TXT;
			evdns_base_resolve_txt(evdns_resolver_base, req->questions[i]->name,
				0, resolver_callback, &myreq);
			waitreq = opt_timeout_upstream;
			while (waitreq > 0) {
				if (!myreq.resolved) { usleep(1000); waitreq--; continue; }
				if (myreq.type == DNS_TXT && myreq.data.txt) {
					DEBUG(" -- send %d %s for %s...", myreq.rr_count, "TXT", req->questions[i]->name);
					for (j = 0; j < myreq.rr_count; ++j) {
						DEBUG("\t%d[parts=%d]: [%s]", j, myreq.data.txt[j].parts, myreq.data.txt[j].text);
						r = evdns_server_request_add_txt_reply(req, req->questions[i]->name,
							&myreq.data.txt[j], myreq.ttl);
						if (r < 0) DEBUG("err %d", r);
						free(myreq.data.txt[j].text);
					}
					free(myreq.data.txt);
					SEND_SOA_AUTH_IF_PRESENT
				} else DEBUG("!?? %d", myreq.type);
				break;
			}
			if (waitreq == 0) DEBUG(" -- %s timeout for %s", "TXT", req->questions[i]->name);
			break;

		case EVDNS_TYPE_AAAA: // 28
			hash = domain_is_blocked(htable, req->questions[i]->name);
			if (hash) {
				DEBUG(" -- Send blackhole %s IP for %s", "AAAA", req->questions[i]->name);
				evdns_server_request_add_aaaa_reply(req,
					req->questions[i]->name, 1, &opt_blackhole_ip6, blackhole_ttl);
				stat.blocked++;
				hash->hit++;
				break;
			}
			DEBUG(" -- Try resolve %s for %s", "AAAA", req->questions[i]->name);
			myreq.type = DNS_IPv6_AAAA;
			evdns_base_resolve_ipv6(evdns_resolver_base, req->questions[i]->name,
				DNS_CNAME_CALLBACK, resolver_callback, &myreq);
			waitreq = opt_timeout_upstream;
			while (waitreq > 0) {
				if (!myreq.resolved) { usleep(1000); waitreq--; continue; }
				if (myreq.type == DNS_IPv6_AAAA && myreq.data.aaaa) {
					if (myreq.cname) {
						DEBUG(" -- send CNAME %s for %s...", myreq.cname, req->questions[i]->name);
						r = evdns_server_request_add_cname_reply(req, req->questions[i]->name,
							myreq.cname, myreq.ttl);
						if (r < 0) DEBUG("err %d", r);
						free(myreq.cname);
					}
					DEBUG(" -- send %d %s for %s...", myreq.rr_count, "IPv6", req->questions[i]->name);
					for (j = 0; j < myreq.rr_count; ++j) {
						r = evdns_server_request_add_aaaa_reply(req,
							req->questions[i]->name, 1, &myreq.data.aaaa[j], myreq.ttl);
						if (r < 0) DEBUG("err %d", r);
					}
					free(myreq.data.aaaa);
					SEND_SOA_AUTH_IF_PRESENT
				} else DEBUG("!?? %d", myreq.type);
				break;
			}
			if (waitreq == 0) DEBUG(" -- %s timeout for %s", "AAAA", req->questions[i]->name);
			break;

		default:
			DEBUG(" -- skipping %s [type=%d class=%d]", req->questions[i]->name,
				req->questions[i]->type, req->questions[i]->dns_question_class);
			break;
		} // switch
	} // for

	r = evdns_server_request_respond(req, 0);
	if (r < 0) DEBUG("Can't send reply");
} // server_callback()

static void *
server_dispatch(void *arg) {
	fprintf(stderr, "Run %s thread\n", "server");
	event_base_dispatch(event_server_base);
	fprintf(stderr, "Exit %s thread\n", "server");
	pthread_exit(NULL);
} // server_dispatch()

static void *
resolver_dispatch(void *arg) {
	fprintf(stderr, "Run %s thread\n", "resolver");
	event_base_dispatch(event_resolver_base);
	fprintf(stderr, "Exit %s thread\n", "resolver");
	pthread_exit(NULL);
} // resolver_dispatch()

// BLACKHOLE WEB SERVER
////////////////////////////

static struct event_base *event_http_base = NULL;
static struct evhttp *http_server = NULL;
static int blackhole_http_socket = -1;

#ifdef EVENT__HAVE_OPENSSL
static SSL_CTX *ctx = NULL;
static struct event_base *event_https_base = NULL;
static struct evhttp *https_server = NULL;
static struct evhttp_bound_socket *https_socket_handle = NULL;
#endif

// HTTP callbacks definitions
typedef int (*function_url_handler_t)(struct evhttp_request *, struct evbuffer *);
int www_blockedpage_handler(struct evhttp_request *, struct evbuffer *);
int www_blocksvg_handler(struct evhttp_request *, struct evbuffer *);
int www_apistatus_handler(struct evhttp_request *, struct evbuffer *);

// Array of URL's served by HTTP
struct http_uri {
	const char *uri;
	const char *content_type; // if NULL - "text/html;charset=utf-8"
	function_url_handler_t handler;
} http_uri_list[] = {
	{ "/block.svg", "image/svg+xml", &www_blocksvg_handler},
	{ "/api_status", NULL, &www_apistatus_handler}, // TODO adapt this if another api port
	{ NULL, NULL, NULL} // end of list
}; // http_uri_list

static void
http_process_request(struct evhttp_request *req, void *arg) {
	int http_code = HTTP_NOTFOUND; // default "Page not found"
	const char *http_message = "Page not found";
	const char *conttype = "text/html; charset=utf8";
	struct evhttp_uri *uri_parsed = NULL;
	struct evbuffer *buf = NULL;
	char *path = NULL;

	uri_parsed = evhttp_uri_parse(req->uri);
	if (!uri_parsed) {
		evhttp_send_error(req, HTTP_BADREQUEST, 0);
		return;
	}

	buf = evbuffer_new();
	if (!buf) {
		evhttp_send_error(req, HTTP_INTERNAL, "Can't allocate memory for reply");
		if (uri_parsed) evhttp_uri_free(uri_parsed);
		return;
	}

	path = evhttp_decode_uri(evhttp_uri_get_path(uri_parsed));
	if (path) {
		struct http_uri *u = http_uri_list;
		while (u->uri) {
			if (0 == strcmp(path, u->uri)) {
				if (u->content_type) conttype = u->content_type;
				http_code = u->handler(req, buf);
				break;
			}
			u++;
		} // while
		free(path);
	} else http_code = HTTP_INTERNAL;

	if (http_code == HTTP_NOTFOUND) {
		http_code = www_blockedpage_handler(req,buf);
	}

	switch (http_code) {
	case HTTP_OK:
		evhttp_add_header(req->output_headers, "Expires", "Mon, 26 Jul 1997 05:00:00 GMT");
		evhttp_add_header(req->output_headers, "Cache-Control", "no-cache, must-revalidate");
		evhttp_add_header(req->output_headers, "Pragma", "no-cache");
		if (strlen(conttype) > 0) {
			evhttp_add_header(req->output_headers, "Content-type", conttype);
		};
		http_message = "OK";
		break;
/*
	case HTTP_UNAUTHORIZED: http_message = "Unauthorized"; break;
	case HTTP_BADREQUEST: http_message = "Wrong request"; break;
	case HTTP_NOTFOUND: http_message = "Not found"; break;
	case HTTP_MOVEPERM: http_message = "Moved Permanently"; break;
*/
	case 451: http_message = "Unavailable For Legal Reasons"; break;
	default:
		http_code = HTTP_INTERNAL;
		http_message = "Internal server error";
	} // switch
	evhttp_send_reply(req, http_code, http_message, buf);

	if (buf) evbuffer_free(buf);
	if (uri_parsed) evhttp_uri_free(uri_parsed);
} // http_process_request()

static void *
http_dispatch(void *arg) {
	if (event_http_base) {
		fprintf(stderr, "Run %s thread\n", "HTTP server");
		event_base_dispatch(event_http_base);
		fprintf(stderr, "Exit %s thread\n", "HTTP server");
	} else fprintf(stderr, "No %s event base\n", "http");
	pthread_exit(NULL);
} // http_dispatch()

#ifdef EVENT__HAVE_OPENSSL
// callback for creating new SSL connection wrapped in OpenSSL bufferevent
static struct bufferevent *bevcb(struct event_base *base, void *arg) {
	return bufferevent_openssl_socket_new(base, -1, SSL_new((SSL_CTX *)arg),
		BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
} // bevcb()

static void *
https_dispatch(void *arg) {
	if (event_https_base) {
		fprintf(stderr, "Run %s thread\n", "HTTPS server");
		event_base_dispatch(event_https_base);
		fprintf(stderr, "Exit %s thread\n", "HTTPS server");
	} else fprintf(stderr, "No %s event base\n", "https");
	pthread_exit(NULL);
} // http_dispatch()
#endif

// Default page for blackhole HTTP server
int www_blockedpage_handler(struct evhttp_request *req, struct evbuffer *buf) {
	if (!req || !buf) return HTTP_INTERNAL;
	W("<html>");
	W("<head><title>Page is blocked</title></head>");
	W("<body bgcolor=white><table width=100%% height=100%%>");
	W("<tr><th><img src=/block.svg width=300 height=300></a>");
	W("<br><br>Page is blocked by your DNS provider !");
	W("</table></body>");
	W("</html>");
	return 451;
} // www_blockedpage_handler()

// SVG image blocked HTTP server
int www_blocksvg_handler(struct evhttp_request *req, struct evbuffer *buf) {
	int cr[4] = {300, 295, 250, 245};
	const char *cc[4] = {"800000", "FF0000", "800000", "FFFFFF"};
	int wx[3] = {20, 208, 396};
	if (!req || !buf) return HTTP_INTERNAL;
	W("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
	// W("<!-- Author: kuzinandrey@yandex.ru 2024-11-01 -->\n");
	W("<svg viewBox=\"0 0 600 600\" xmlns=\"http://www.w3.org/2000/svg\">");
	for (int i = 0; i < 4; ++i)
		W("<circle cx=\"300\" cy=\"300\" r=\"%d\" fill=\"#%s\"/>",cr[i],cc[i]);
	for (int i = 0; i < 3; ++i)
		W("<path d=\"M %d 230 l 35 0 l 25 110 l 20 -110 l 30 0 l 15 110 l 25 -110"
		" l 35 0 l -37 150 l -40 0 l -15 -80 l -15 80 l -40 0\""
		" fill=\"#000000\" stroke=\"#000000\"/>", wx[i]);
	W("<path d=\"M 100 450 l 350 -350 l 50 50 l -350 350\" fill=\"#800000\" stroke=\"#800000\"/>");
	W("<path d=\"M 100 458 l 357 -358 l 49 37 l -367 367\" fill=\"#FF0000\" stroke=\"#FF0000\"/>");
	W("</svg>");
	return HTTP_OK;
} // www_blocksvg_handler()

// API status page
int www_apistatus_handler(struct evhttp_request *req, struct evbuffer *buf) {
	if (!req || !buf) return HTTP_INTERNAL;
	W("<html>");
	W("<head><title>API status page</title></head>");
	W("<body bgcolor=white link=blue>");
	W("<pre>");
	W("DNS requests total:\n");
	W("%s=%" PRIu64 "\n", "Requests", stat.requests);
	W("%s=%" PRIu64 "\n", "Resolves", stat.resolves);
	W("%s=%" PRIu64 "\n", "Blocked", stat.blocked);
	W("\nDNS requests by type:\n");
	W("%s=%" PRIu64 "\n", "A", stat.type_a);
	W("%s=%" PRIu64 "\n", "PTR", stat.type_ptr);
	W("%s=%" PRIu64 "\n", "AAAA", stat.type_aaaa);
	W("%s=%" PRIu64 "\n", "CNAME", stat.type_cname);
	W("%s=%" PRIu64 "\n", "NS", stat.type_ns);
	W("%s=%" PRIu64 "\n", "MX", stat.type_mx);
	W("%s=%" PRIu64 "\n", "SOA", stat.type_soa);
	W("%s=%" PRIu64 "\n", "TXT", stat.type_txt);
	W("%s=%" PRIu64 "\n", "SOA_AUTH", stat.type_soa_auth);
	W("%s=%" PRIu64 "\n", "Unknown", stat.type_unknown);
	W("</pre>");
	W("</html>");
	return HTTP_OK;
} // www_blockedpage_handler()

// DATA FILE
////////////////////////////

static int
load_file_in_memory(const char *file_name, char **buffer, long *file_size,
	struct str_hash **htable[], size_t *line_count, size_t *inserted_count,
	size_t *skipped_count)
{
	FILE *f = NULL;
	char *p;
	size_t len, remain, lines, inserted, skipped;
	struct str_hash *hr;

	*file_size = 0;
	f = fopen(file_name,"r");
	if (!f) {
		fprintf(stderr, "ERROR: Can't open file %s - %s\n", file_name, strerror(errno));
		return -1;
	}

	if (-1 == fseek(f, 0, SEEK_END)) {
		fprintf(stderr, "ERROR: Can't seek file - %s\n", strerror(errno));
		fclose(f);
		return -1;
	} else *file_size = ftell(f);

	rewind(f);

	*buffer = malloc(*file_size + 1); // + 1 for '\0'
	if (!*buffer) {
		fprintf(stderr, "ERROR: Can't allocate memory %ld bytes for file %s\n", *file_size, file_name);
		goto error;
	}

	p = *buffer;
	remain = *file_size;
	lines = inserted = skipped = 0;
	while (remain > 0) {
		if (!fgets(p, remain + 1, f)) break;

		len = strlen(p);
		p[len-1] = 0;
		if ((hr = domain_is_blocked(*htable, p))) {
			// fprintf(stderr,"skipped: %s by %s\n", p, hr->str);
			skipped++;
		} else {
			if (0 == insert_str_hash(*htable, p)) {
				// fprintf(stderr,"%ld: %s = %ld (rem %ld)\n", lines + 1, p, len, remain);
				inserted++;
			}
		}
		p += len;
		remain -= len;
		lines++;
	}
	fclose(f);

	*line_count = lines;
	*inserted_count = inserted;
	*skipped_count = skipped;

	printf("Load %ld zones in memory:\n"
		"\t- inserted in hash: %ld\n"
		"\t- skipped: %ld\n"
		"\t- file size: %ld\n",
		*line_count, *inserted_count,
		*skipped_count, *file_size);

	return 0;
error:
	fclose(f);
	return -1;
} // load_file_in_memory()


// SIGNAL HANDLERS
////////////////////////////

static void
signal_exit_cb(evutil_socket_t fd, short event, void *arg)
{
	if (event_resolver_base)
		event_base_loopbreak(event_resolver_base);

	if (event_server_base)
		event_base_loopbreak(event_server_base);

	if (event_http_base)
		event_base_loopbreak(event_http_base);

#ifdef EVENT__HAVE_OPENSSL
	if (event_https_base)
		event_base_loopbreak(event_https_base);
#endif

	if (event_main_base)
		event_base_loopbreak(event_main_base);
} // exit_signal_cb()

static void
signal_hup_cb(evutil_socket_t fd, short event, void *arg)
{
	struct str_hash **newhtable = NULL;
	char *newhtable_data = NULL;

	struct str_hash **oldhtable = NULL;
	char *oldhtable_data = NULL;

	long newhtable_data_size = 0;
	size_t newline_count = 0;
	size_t newhtable_inserted_count = 0;
	size_t newhtable_skipped_count = 0;

	if (!opt_file_name) {
		fprintf(stderr, "ERROR: Can't reload file, filename is NULL\n");
		return;
	}

	newhtable = calloc(hash_table_size + 1, sizeof(struct str_hash *));
	if (!newhtable) {
		fprintf(stderr, "ERROR: Can't allocate memory for hash table\n");
		return;
	}

	if (0 != load_file_in_memory(opt_file_name, &newhtable_data, &newhtable_data_size,
		&newhtable, &newline_count, &newhtable_inserted_count, &newhtable_skipped_count)
	) {
		fprintf(stderr, "ERROR: Can't load file %s in memory (%ld bytes)\n",
			opt_file_name, newhtable_data_size);
		free(newhtable);
		return;
	};

	// save pointers for free
	oldhtable = htable;
	oldhtable_data = htable_data;

	// set new values
	htable = newhtable;
	htable_data = newhtable_data;
	htable_data_size = newhtable_data_size;
	line_count = newline_count;
	htable_inserted_count = newhtable_inserted_count;
	htable_skipped_count = newhtable_skipped_count;

	// wait some time before clean memory (hash very fast, and try not use mutex)
	sleep(1);

	if (oldhtable) { clean_str_hash(oldhtable); free(oldhtable); }
	if (oldhtable_data) free(oldhtable_data);
} // exit_hup_cb()


static void
usage(const char *progname) {
	printf(
	"\n"
	"DNS blackhole server for resolve list of domain names to blackhole IP.\n"
	"Can be used to block some ads, malware, pop-ups sites or similar tasks.\n"
	"Author: Kuzin Andrey <kuzinandrey@yandex.ru>\n"
	"License: MIT\n"
	"Vcs: https://github.com/KuzinAndrey/dns-blackhole\n"
	"Version: %s\n"
	"\n"
	"Usage:\n"
	"\t%s [opts] <domains.txt>\n"
	"Options:\n"
	"\t-h        - this help\n"
	"\t-v        - version\n"
	"\t-d        - debug mode (increase verbosity)\n"
	"\t-n <ip>   - add backend DNS server IP address as resolver (can be multiple time),\n"
	"\t            if no any such option then try to use system configured NS servers\n"
	"\t-t <n>    - backend resolve timeout n*1000 microsec (default %d)\n"
	"\t-4 <ip>   - blackhole IPv4 address\n"
	"\t-6 <ip6>  - blackhole IPv6 address\n"
#ifdef EVENT__HAVE_OPENSSL
	"\t-s        - act as the blackhole (up server on HTTP/80 and HTTPS/443 if -k/-c provided)\n"
	"\t-k <file> - SSL key file (for HTTPS), usually self signed\n"
	"\t-c <file> - SSL cert file (for HTTPS)\n"
#else
	"\t-s        - act as the blackhole (up server on HTTP/80)\n"
#endif
//	"\t-a <port> - activate web API on <port>\n" // TODO api page on another port ?!
	"Data:\n"
	"\t<domain.txt> - text file with list of domain names (one name on line),\n"
	"\t               which resolve by server as blackhole IP\n"
	"Signals:\n"
	"\tSIGHUP    - reload <domain.txt> file content (in run time)\n"
	"\n"
	, PROGRAM_VERSION, progname, opt_timeout_upstream);
	exit(0);
} // usage()

int main(int argc, char **argv) {
	int mainret = 0;
	int ret = 0;

	pthread_t server_thread;
	pthread_t resolver_thread;
	pthread_t blackhole_http_thread;
#ifdef EVENT__HAVE_OPENSSL
	pthread_t blackhole_https_thread;
#endif

	evutil_socket_t dns_udpsock = -1;
	struct evdns_server_port *server_udp_port = NULL;

	evutil_socket_t dns_tcpsock = -1;
	struct evdns_server_port *server_tcp_port = NULL;
	struct evconnlistener *tcp_listener = NULL;

	struct sockaddr_in server_addr;

	char *ns_list[100] = {0};
	size_t backend_ns_servers_count = 0;


	if (argc < 2) usage(argv[0]);
#define OPT_ERROR_IP_MUST_PROVIDE \
	"ERROR: You must provide %s address for %d option \"%s\"\n"
#define OPT_ERROR_WRONG_IP \
	"ERROR: Wrong %s address provided \"%s\"\n"
#define OPT_WRONG_VALUE_FOR_OPT \
	"ERROR: Wrong value for %d option \"%s\" = \"%s\"\n"

	// Parse command line options
	for (int i = 1; i < argc; i++)
	if (0 == strcmp(argv[i], "-h")) {
		usage(argv[0]);
	} else if (0 == strcmp(argv[i], "-v")) { // Version
		printf("%s\n", PROGRAM_VERSION);
		return 0;
	} else if (0 == strcmp(argv[i], "-d")) { // Debug
		opt_debug = 1;
		// event_enable_debug_logging(EVENT_DBG_ALL);
	} else if (0 == strcmp(argv[i], "-n")) { // NS server
		static struct in_addr test_ns_ip = {0};
		if (i + 1 >= argc) {
			fprintf(stderr, OPT_ERROR_IP_MUST_PROVIDE, "IPv4", i, argv[i]);
			return 1;
		} else i++;
		if (backend_ns_servers_count + 1 >= sizeof(ns_list)/sizeof(ns_list[0])) {
			fprintf(stderr, "ERROR: Backend server table is full on \"%s\" value\n", argv[i]);
			return 1;
		}
		if (!inet_pton(AF_INET, argv[i], &test_ns_ip)) {
			fprintf(stderr, OPT_ERROR_WRONG_IP, "IPv4", argv[i]);
			return 1;
		}
		ns_list[backend_ns_servers_count++] = argv[i];
	} else if (0 == strcmp(argv[i], "-t")) { // Timeout
		char *e; long v = 0;
		if (i + 1 >= argc) {
			fprintf(stderr, "ERROR: You must provide timeout integer value for option \"%s\"\n", argv[i]);
			return 1;
		} else i++;
		v = strtol(argv[i], &e, 10);
		if (*e != 0 || (v <= 0 || v > 60000)) {
			fprintf(stderr, OPT_WRONG_VALUE_FOR_OPT, i - 1, argv[i - 1], argv[i]);
		} else opt_timeout_upstream = v;
	} else if (0 == strcmp(argv[i], "-4")) { // Blackhole IPv4
		if (i + 1 >= argc) {
			fprintf(stderr, OPT_ERROR_IP_MUST_PROVIDE, "IPv4", i, argv[i]);
			return 1;
		} else i++;
		if (!inet_pton(AF_INET, argv[i], &opt_blackhole_ip4)) {
			fprintf(stderr, OPT_ERROR_WRONG_IP, "IPv4", argv[i]);
			return 1;
		} else {
			if (opt_blackhole_ip4_set)
				fprintf(stderr, "WARNING: Remember only last address for option \"%s\"\n", argv[i - 1]);
			opt_blackhole_ip4_set = 1;
		}
	} else if (0 == strcmp(argv[i], "-6")) { // Blackhole IPv6
		if (i + 1 >= argc) {
			fprintf(stderr, OPT_ERROR_IP_MUST_PROVIDE, "IPv6", i, argv[i]);
			return 1;
		} else i++;
		if (!inet_pton(AF_INET6, argv[i], &opt_blackhole_ip6)) {
			fprintf(stderr, OPT_ERROR_WRONG_IP, "IPv6", argv[i]);
			return 1;
		} else {
			if (opt_blackhole_ip6_set)
				fprintf(stderr, "WARNING: Remember only last address for option \"%s\"\n", argv[i - 1]);
			opt_blackhole_ip6_set = 1;
		}
	} else if (0 == strcmp(argv[i], "-s")) { // Blackhole HTTP(S) server running
		opt_blackhole_server = 1;
#ifdef EVENT__HAVE_OPENSSL
	} else if (0 == strcmp(argv[i], "-k")) { // HTTPS server key file name
		if (i + 1 >= argc) {
			fprintf(stderr, "ERROR: You must provide file name for %d option \"%s\"\n", i, argv[i]);
			return 1;
		} else i++;
		opt_https_key_file = argv[i];
#ifdef EVENT__HAVE_UNISTD_H
		if (0 != access(opt_https_key_file, R_OK)) {
			fprintf(stderr, "ERROR: Can't open file %s - %s\n", opt_https_key_file, strerror(errno));
			return 1;
		}
#endif
	} else if (0 == strcmp(argv[i], "-c")) { // HTTPS server cert file name
		if (i + 1 >= argc) {
			fprintf(stderr, "ERROR: You must provide file name for %d option \"%s\"\n", i, argv[i]);
			return 1;
		} else i++;
		opt_https_cert_file = argv[i];
#ifdef EVENT__HAVE_UNISTD_H
		if (0 != access(opt_https_cert_file, R_OK)) {
			fprintf(stderr, "ERROR: Can't open file %s - %s\n", opt_https_cert_file, strerror(errno));
			return 1;
		}
#endif
#endif /* EVENT__HAVE_OPENSSL */
/*
	// TODO we really need API statistics page on another port ?!
	} else if (0 == strcmp(argv[i], "-a")) { // Activate web API on <port>
		char *e; long v = 0;
		if (i + 1 >= argc) {
			fprintf(stderr, "ERROR: You must provide API port value for option \"%s\"\n", argv[i]);
			return 1;
		} else i++;
		v = strtol(argv[i], &e, 10);
		if (*e != 0 || (v <= 0 || v > 65535)) {
			fprintf(stderr, OPT_WRONG_VALUE_FOR_OPT, i - 1, argv[i - 1], argv[i]);
		} else opt_api_port = v;
*/
	} else {
		opt_file_name = argv[i]; // save file name
#ifdef EVENT__HAVE_UNISTD_H
		if (0 == access(opt_file_name, R_OK))
#endif
		break; // if no file

		fprintf(stderr, "ERROR: Can't open file \"%s\" on unknown option number %d\n", argv[i], i);
		return 1;
	}

	if (!opt_file_name) {
		fprintf(stderr, "ERROR: No any file name provided\n");
		fprintf(stderr, "Use for help:\n\t%s -h\n", argv[0]);
		return 1;
	}

	if (!opt_blackhole_ip4_set) {
		inet_pton(AF_INET, "127.0.0.1", &opt_blackhole_ip4);
		opt_blackhole_ip4_set = 1;
	}

	if (!opt_blackhole_ip6_set) {
		inet_pton(AF_INET6, "::1", &opt_blackhole_ip6);
		opt_blackhole_ip6_set = 1;
	}

	htable = calloc(hash_table_size + 1, sizeof(struct str_hash *));
	if (!htable) {
		fprintf(stderr, "ERROR: Can't allocate memory for hash table\n");
		goto exit_error;
	}

	if (0 != load_file_in_memory(opt_file_name, &htable_data, &htable_data_size,
		&htable, &line_count, &htable_inserted_count, &htable_skipped_count)
	) {
		fprintf(stderr, "ERROR: Can't load file %s in memory (%ld bytes)\n",
			opt_file_name, htable_data_size);
		goto exit_error;
	};

	evthread_use_pthreads();
	DEBUG("Libevent version: \"%s\"",event_get_version());

	event_main_base = event_base_new();
	if (!event_main_base) {
		fprintf(stderr, "ERROR: Can't create new %s\n","event_main_base");
		goto exit_error;
	}

	event_server_base = event_base_new();
	if (!event_server_base) {
		fprintf(stderr, "ERROR: Can't create new %s\n","event_server_base");
		goto exit_error;
	}

	event_resolver_base = event_base_new();
	if (!event_resolver_base) {
		fprintf(stderr, "ERROR: Can't create new %s\n","event_resolver_base");
		goto exit_error;
	}

	evdns_server_base = evdns_base_new(event_server_base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
	if (!evdns_server_base) {
		fprintf(stderr, "ERROR: Can't create new %s\n","evdns_server_base");
		goto exit_error;
	}

	evdns_resolver_base = evdns_base_new(event_resolver_base, 0);
	if (!evdns_resolver_base) {
		fprintf(stderr, "ERROR: Can't create new %s\n","evdns_resolver_base");
		goto exit_error;
	}

	backend_ns_servers_count = 0;
	for (size_t i = 0; i < sizeof(ns_list) / sizeof(ns_list[0]); i++) {
		if (!ns_list[i]) continue;
		ret = evdns_base_nameserver_ip_add(evdns_resolver_base, ns_list[i]);
		if (ret) {
			fprintf(stderr,"ERROR: Can't add nameserver %s\n", ns_list[i]);
			goto exit_error;
		} else {
			printf("Add NS[%ld] for resolver: %s\n", i, ns_list[i]);
			backend_ns_servers_count++;
		}
	}

	if (!backend_ns_servers_count) {
		struct sockaddr get_ns_sa;
		int get_ns_idx = 0;
		char ipa[128];
		if (
#ifdef _WIN32
			evdns_base_config_windows_nameservers(evdns_resolver_base)
#else
			evdns_base_resolv_conf_parse(evdns_resolver_base,
				DNS_OPTION_NAMESERVERS, "/etc/resolv.conf")
#endif
		) {
			fprintf(stderr, "ERROR: Can't configure nameservers\n");
			goto exit_error;
		}

		backend_ns_servers_count = evdns_base_count_nameservers(evdns_resolver_base);
		printf("Set system nameservers: %ld\n", backend_ns_servers_count);
		while (-1 != evdns_base_get_nameserver_addr(evdns_resolver_base,
			get_ns_idx, &get_ns_sa, sizeof(get_ns_sa))) {
			switch (get_ns_sa.sa_family) {
				case AF_INET: {
					struct sockaddr_in *sin = (struct sockaddr_in *)&get_ns_sa;
					evutil_inet_ntop(AF_INET, &sin->sin_addr, ipa, sizeof(ipa));
				} break;
				case AF_INET6: {
					struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&get_ns_sa;
					evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, ipa, sizeof(ipa));
				} break;
			}
			printf("\t[%d] %s (%s)\n", get_ns_idx, ipa,
				get_ns_sa.sa_family == AF_INET ? "IPv4" : "IPv6");
			get_ns_idx++;
		}
	}

	if (!backend_ns_servers_count) {
		fprintf(stderr, "ERROR: Can't configure any backend DNS server for resolve names\n");
		goto exit_error;
	}

	if (opt_blackhole_ip4_set) {
		printf("Blackhole IP: %s\n", inet_ntoa(opt_blackhole_ip4));
	}

	// DNS server address
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DNS_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	// Create DNS server on UDP 53 port
	dns_udpsock = socket(PF_INET, SOCK_DGRAM, 0);
	if (dns_udpsock == -1) {
		fprintf(stderr, "ERROR: Can't create socket: %s\n", strerror(errno));
		goto exit_error;
	}
	evutil_make_socket_nonblocking(dns_udpsock);
	if (bind(dns_udpsock, (struct sockaddr*)&server_addr, sizeof(server_addr))<0) {
		fprintf(stderr, "ERROR: Can't bind %s socket: %s\n", "UDP", strerror(errno));
		goto exit_error;
	}
	server_udp_port = evdns_add_server_port_with_base(event_server_base,
		dns_udpsock, 0, server_callback, NULL);
	if (!server_udp_port) {
		fprintf(stderr, "ERROR: Can't add server port\n");
		goto exit_error;
	} else printf("DNS server listening on %s port %d\n", "UDP", DNS_PORT);

	// Create DNS server on TCP 53 port
	tcp_listener = evconnlistener_new_bind(event_server_base, NULL, NULL,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 128,
			(struct sockaddr*)&server_addr, sizeof(server_addr));
	if (!tcp_listener) {
		fprintf(stderr, "ERROR: Can't call %s()\n", "evconnlistener_new_bind");
		goto exit_error;
	}
	server_tcp_port = evdns_add_server_port_with_listener(event_server_base,
		tcp_listener, 0, server_callback, NULL);
	if (!server_tcp_port) {
		fprintf(stderr, "ERROR: Can't add server port\n");
		goto exit_error;
	} else printf("DNS server listening on %s port %d\n", "TCP", DNS_PORT);

	// Blackhole server
	if (opt_blackhole_server) {
		// Create HTTP blackhole server
		event_http_base = event_init();
		if (!event_http_base) {
			fprintf(stderr, "ERROR: Can't call %s()\n", "event_init");
			goto exit_error;
		}

		http_server = evhttp_new(event_http_base);
		if (!http_server) {
			fprintf(stderr, "ERROR: Can't call %s()\n", "evhttp_new");
			goto exit_error;
		}

		evhttp_set_gencb(http_server, http_process_request, NULL);

		blackhole_http_socket = evhttp_bind_socket(http_server, "0.0.0.0", 80);
		if (blackhole_http_socket < 0) {
			fprintf(stderr, "ERROR: Can't call %s()\n", "http_bind_socket");
			goto exit_error;
		};

#ifdef EVENT__HAVE_OPENSSL
		if (opt_https_key_file && opt_https_cert_file) {
			// Create HTTPS blackhole server
			event_https_base = event_init();
			if (!event_https_base) {
				fprintf(stderr,"ERROR: Can't call %s()\n", "event_init");
				goto exit_error;
			}

			https_server = evhttp_new(event_https_base);
			if (!https_server) {
				fprintf(stderr, "ERROR: Can't call %s()\n", "evhttp_new");
				goto exit_error;
			}

			// Init OpenSSL
			SSL_library_init();
			SSL_load_error_strings();
			OpenSSL_add_all_algorithms();

			DEBUG("OpenSSL version: \"%s\"",SSLeay_version(SSLEAY_VERSION));

			// Init OpenSSL TLS context
			ctx = SSL_CTX_new(TLS_server_method());
			if (!ctx) {
				fprintf(stderr, "ERROR: Can't call %s()\n", "SSL_CTX_new");
				ERR_print_errors_fp(stderr);
				goto exit_error;
			}

			if (1 != SSL_CTX_use_certificate_chain_file(ctx, opt_https_cert_file)) {
				fprintf(stderr, "ERROR: Can't call %s()\n", "SSL_CTX_use_certificate_chain_file");
				ERR_print_errors_fp(stderr);
				goto exit_error;
			}

			if (1 != SSL_CTX_use_PrivateKey_file(ctx, opt_https_key_file, SSL_FILETYPE_PEM)) {
				fprintf(stderr, "ERROR: Can't call %s()\n", "SSL_CTX_use_PrivateKey_file");
				ERR_print_errors_fp(stderr);
				goto exit_error;
			}

			if (1 != SSL_CTX_check_private_key(ctx)) {
				fprintf(stderr, "ERROR: Can't call %s()\n", "SSL_CTX_check_private_key");
				ERR_print_errors_fp(stderr);
				goto exit_error;
			}

			// Prepare callbacks
			evhttp_set_bevcb(https_server, bevcb, ctx); // magic for use SSL in evhttp
			evhttp_set_gencb(https_server, http_process_request, NULL);

			// Create HTTPS server
			https_socket_handle = evhttp_bind_socket_with_handle(https_server, "0.0.0.0", 443);
			if (!https_socket_handle) {
				fprintf(stderr, "ERROR: Can't call %s()\n", "evhttp_bind_socket_with_handle");
				goto exit_error;
			};

		} else {
			const char *unknown_file = "";
			const char *unknown_option = "";
			if (!opt_https_key_file && !opt_https_cert_file) {
				unknown_file = "key and cert";
				unknown_option = "-k and -c";
			} else if (!opt_https_key_file) {
				unknown_file = "primary key";
				unknown_option = "-k";
			} else if (!opt_https_cert_file) {
				unknown_file = "cert chain";
				unknown_option = "-c";
			}
			fprintf(stderr, "WARNING: Can't create HTTPS server"
				" without %s file. Use %s option !\n", unknown_file, unknown_option);
		}

		if (https_server && 0 != pthread_create(&blackhole_https_thread, NULL, https_dispatch, NULL)) {;
			fprintf(stderr, "ERROR: Can't create pthread %s\n", "http_dispatch");
			goto exit_error;
		}
#endif /* EVENT__HAVE_OPENSSL */

		if (http_server && 0 != pthread_create(&blackhole_http_thread, NULL, http_dispatch, NULL)) {;
			fprintf(stderr, "ERROR: Can't create pthread %s\n", "http_dispatch");
			goto exit_error;
		}

	} // opt_blackhole_server

	if (0 != pthread_create(&server_thread, NULL, server_dispatch, NULL)) {
		fprintf(stderr, "ERROR: Can't create pthread %s\n", "server_dispatch");
		goto exit_error;
	};

	if (0 != pthread_create(&resolver_thread, NULL, resolver_dispatch, NULL)) {
		fprintf(stderr, "ERROR: Can't create pthread %s\n", "resolver_dispatch");
		goto exit_error;
	};

	sig_int = evsignal_new(event_main_base, SIGINT, signal_exit_cb, NULL);
	if (sig_int) event_add(sig_int, NULL);
	sig_term = evsignal_new(event_main_base, SIGTERM, signal_exit_cb, NULL);
	if (sig_term) event_add(sig_term, NULL);
	sig_quit = evsignal_new(event_main_base, SIGQUIT, signal_exit_cb, NULL);
	if (sig_quit) event_add(sig_quit, NULL);
	sig_hup = evsignal_new(event_main_base, SIGHUP, signal_hup_cb, NULL);
	if (sig_hup) event_add(sig_hup, NULL);

	fflush(stdout);

	event_base_dispatch(event_main_base);

	pthread_join(server_thread, NULL);
	pthread_join(resolver_thread, NULL);
	if (opt_blackhole_server) {
		if (http_server) pthread_join(blackhole_http_thread, NULL);
#ifdef EVENT__HAVE_OPENSSL
		if (https_server) pthread_join(blackhole_https_thread, NULL);
#endif
	}

	goto exit_ok;

exit_error:
	mainret = 1;

exit_ok:
	if (http_server) evhttp_free(http_server);
	if (event_http_base) event_base_free(event_http_base);
	if (blackhole_http_socket != -1) close(blackhole_http_socket);

#ifdef EVENT__HAVE_OPENSSL
	if (https_server) evhttp_free(https_server);
	if (event_https_base) event_base_free(event_https_base);
//	if (blackhole_https_socket != -1) close(blackhole_https_socket);
	if (ctx) SSL_CTX_free(ctx);
	EVP_cleanup();
#endif

	if (server_udp_port) evdns_close_server_port(server_udp_port);
	if (server_tcp_port) evdns_close_server_port(server_tcp_port);

	if (evdns_server_base) evdns_base_free(evdns_server_base, 1);
	if (evdns_resolver_base) evdns_base_free(evdns_resolver_base, 1);

	if (event_server_base) event_base_free(event_server_base);
	if (event_resolver_base) event_base_free(event_resolver_base);

	if (sig_int) { event_del(sig_int); event_free(sig_int); }
	if (sig_term) { event_del(sig_term); event_free(sig_term); }
	if (sig_quit) { event_del(sig_quit); event_free(sig_quit); }
	if (sig_hup) {  event_del(sig_hup); event_free(sig_hup); }

	if (event_main_base) event_base_free(event_main_base);

	if (dns_udpsock != -1) close(dns_udpsock);
	if (dns_tcpsock != -1) close(dns_tcpsock);

	if (htable) { clean_str_hash(htable); free(htable); }
	if (htable_data) free(htable_data);

	return mainret;
} // main()
