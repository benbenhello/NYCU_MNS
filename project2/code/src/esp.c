#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

#define DEBUG

EspHeader esp_hdr_rec;

const char *get_sadb_msg_type(int type)
{
	static char buf[100];
	switch (type) {
	case SADB_RESERVED:	return "Reserved";
	case SADB_GETSPI:	return "Get SPI";
	case SADB_UPDATE:	return "Update";
	case SADB_ADD:		return "Add";
	case SADB_DELETE:	return "Delete";
	case SADB_GET:		return "Get";
	case SADB_ACQUIRE:	return "Acquire";
	case SADB_REGISTER:	return "Register";
	case SADB_EXPIRE:	return "Expire";
	case SADB_FLUSH:	return "Flush";
	case SADB_DUMP:		return "Dump";
	default:			sprintf(buf, "[Unknown type %d]", type);
						return buf;
	}
}

const char *get_sadb_satype(int type)
{
	static char buf[100];
	switch (type) {
	case SADB_SATYPE_UNSPEC:	return "Unspecified";
	case SADB_SATYPE_AH:		return "IPsec AH";
	case SADB_SATYPE_ESP:		return "IPsec ESP";
	case SADB_SATYPE_RSVP:		return "RSVP";
	case SADB_SATYPE_OSPFV2:	return "OSPFv2";
	case SADB_SATYPE_RIPV2:		return "RIPv2";
	case SADB_SATYPE_MIP:		return "Mobile IP";
	default:					sprintf(buf, "[Unknown satype %d]", type);
								return buf;
	}
}

const char *get_auth_alg(int alg)
{
	static char buf[100];
	switch (alg) {
	case SADB_AALG_NONE:		return "None";
	case SADB_AALG_MD5HMAC:		return "HMAC-MD5";
	case SADB_AALG_SHA1HMAC:	return "HMAC-SHA-1";
#ifdef SADB_X_AALG_MD5
	case SADB_X_AALG_MD5:		return "Keyed MD5";
#endif
#ifdef SADB_X_AALG_SHA
	case SADB_X_AALG_SHA:		return "Keyed SHA-1";
#endif
#ifdef SADB_X_AALG_NULL
	case SADB_X_AALG_NULL:		return "Null";
#endif
#ifdef SADB_X_AALG_SHA2_256
	case SADB_X_AALG_SHA2_256:	return "SHA2-256";
#endif
#ifdef SADB_X_AALG_SHA2_384
	case SADB_X_AALG_SHA2_384:	return "SHA2-384";
#endif
#ifdef SADB_X_AALG_SHA2_512
	case SADB_X_AALG_SHA2_512:	return "SHA2-512";
#endif
	default:					sprintf(buf, "[Unknown authentication algorithm %d]", alg);
								return buf;
	}
}

const char *get_encrypt_alg(int alg)
{
	static char buf[100];
	switch (alg) {
	case SADB_EALG_NONE:		return "None";
	case SADB_EALG_DESCBC:		return "DES-CBC";
	case SADB_EALG_3DESCBC:		return "3DES-CBC";
	case SADB_EALG_NULL:		return "Null";
#ifdef SADB_X_EALG_CAST128CBC
	case SADB_X_EALG_CAST128CBC:	return "CAST128-CBC";
#endif
#ifdef SADB_X_EALG_BLOWFISHCBC
	case SADB_X_EALG_BLOWFISHCBC:	return "Blowfish-CBC";
#endif
#ifdef SADB_X_EALG_AES
	case SADB_X_EALG_AES:			return "AES";
#endif
	default:					sprintf(buf, "[Unknown encryption algorithm %d]", alg);
								return buf;
	}
}

const char *get_sa_state(int state)
{
	static char buf[100];
	switch (state) {
	case SADB_SASTATE_LARVAL:	return "Larval";
	case SADB_SASTATE_MATURE:	return "Mature";
	case SADB_SASTATE_DYING:	return "Dying";
	case SADB_SASTATE_DEAD:		return "Dead";
	default:					sprintf(buf, "[Unknown SA state %d]", state);
								return buf;
	}
}

const char *get_sadb_alg_type(int alg, int authenc)
{
	if (authenc == SADB_EXT_SUPPORTED_AUTH) {
		return get_auth_alg(alg);
	} else {
		return get_encrypt_alg(alg);
	}
}

void sa_print(struct sadb_ext *ext, uint8_t *key)
{
	struct sadb_sa *sa = (struct sadb_sa *)ext;
	printf(" SA: SPI=%x Replay Window=%d State=%s\n",
		ntohl(sa->sadb_sa_spi), sa->sadb_sa_replay,
		get_sa_state(sa->sadb_sa_state));
	printf("  Authentication Algorithm: %s\n",
		get_auth_alg(sa->sadb_sa_auth));
	printf("  Encryption Algorithm: %s\n",
		get_encrypt_alg(sa->sadb_sa_encrypt));
	if (sa->sadb_sa_flags & SADB_SAFLAGS_PFS)
		printf("  Perfect Forward Secrecy\n");
}

void supported_print(struct sadb_ext *ext)
{
	struct sadb_supported *sup = (struct sadb_supported *)ext;
	struct sadb_alg *alg;
	int len;

	printf(" Supported %s algorithms:\n",
		sup->sadb_supported_exttype == SADB_EXT_SUPPORTED_AUTH ?
		"authentication" :
		"encryption");
	len = sup->sadb_supported_len * 8;
	len -= sizeof(*sup);
	if (len == 0) {
		printf("  None\n");
		return;
	}
	for (alg = (struct sadb_alg *)(sup + 1); len>0; len -= sizeof(*alg), alg++) {
		printf("  %s ivlen %d bits %d-%d\n",
			get_sadb_alg_type(alg->sadb_alg_id, sup->sadb_supported_exttype),
			alg->sadb_alg_ivlen, alg->sadb_alg_minbits, alg->sadb_alg_maxbits);
	}
}

void key_print(struct sadb_ext *ext, uint8_t *returnkey)
{
	struct sadb_key *key = (struct sadb_key *)ext;
	int bits;
	unsigned char *p;
	printf("-----------------------------------------------------\n");
	printf(" %s key, %d bits: 0x",
		key->sadb_key_exttype == SADB_EXT_KEY_AUTH ?
		"Authentication" : "Encryption",
		key->sadb_key_bits);
	for (p = (unsigned char *)(key + 1), bits = key->sadb_key_bits;
			bits > 0; p++, bits -= 8)
		printf("%02x", *p);
	printf("\n");
}

void print_sadb_msg(struct sadb_msg *msg, int msglen, uint8_t *key)
{
	struct sadb_ext *ext;

	if (msglen != msg->sadb_msg_len * 8) {
		printf("SADB Message length (%d) doesn't match msglen (%d)\n",
			msg->sadb_msg_len * 8, msglen);
		return;
	}
	if (msg->sadb_msg_version != PF_KEY_V2) {
		printf("SADB Message version not PF_KEY_V2\n");
		return;
	}
	printf("SADB Message %s, errno %d, satype %s, seq %d, pid %d\n",
		get_sadb_msg_type(msg->sadb_msg_type), msg->sadb_msg_errno,
		get_sadb_satype(msg->sadb_msg_satype), msg->sadb_msg_seq,
		msg->sadb_msg_pid);
	if (msg->sadb_msg_errno != 0)
		printf(" errno %s\n", strerror(msg->sadb_msg_errno));
	if (msglen == sizeof(struct sadb_msg))
		return;	/* no extensions */
	msglen -= sizeof(struct sadb_msg);
	ext = (struct sadb_ext *)(msg + 1);
	while (msglen > 0) {
		switch (ext->sadb_ext_type) {
		case SADB_EXT_RESERVED:
		case SADB_EXT_SA:
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
					key_print(ext, key); break;
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
		case SADB_EXT_SENSITIVITY:
		case SADB_EXT_PROPOSAL:
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
		case SADB_EXT_SPIRANGE:
		default:
		}
		msglen -= ext->sadb_ext_len << 3;
		ext = (char *)ext + (ext->sadb_ext_len << 3);
	}
}


void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)

    int s;
	char buf[4096];
	struct sadb_msg msg;
	int goteof;
    s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

	if(s < 0)
        printf("[get_ik]: socket error");

	/* Build and write SADB_DUMP request */
	bzero(&msg, sizeof(msg));
	msg.sadb_msg_version = PF_KEY_V2;
	msg.sadb_msg_type = SADB_DUMP;
	msg.sadb_msg_satype = type;
	msg.sadb_msg_len = sizeof(msg) / 8;
	msg.sadb_msg_pid = getpid();
	printf("Sending dump message:\n");
	print_sadb_msg(&msg, sizeof(msg), key);

	if(write(s, &msg, sizeof(msg)) != sizeof(msg))
        printf("[get_ik]: write error");

	printf("\nMessages returned:\n");
	/* Read and print SADB_DUMP replies until done */
	goteof = 0;
	while (goteof == 0) {
		int msglen;
		struct sadb_msg *msgp;

		msglen = read(s, &buf, sizeof(buf));
		msgp = (struct sadb_msg *)&buf;
		print_sadb_msg(msgp, msglen, key);
		if (msgp->sadb_msg_seq == 0)
			goteof = 1;
	}
	close(s);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb

    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP
    struct esp_header *esphdr = (struct esp_header *)esp_pkt;

    self->hdr.seq = esphdr->seq;
    self->hdr.spi = esphdr->spi;

#ifdef DEBUG
    printf("ESP seq: %d\n",ntohl(esphdr->seq));
    printf("ESP spi: %x\n",ntohl(esphdr->spi));
#endif

    return esp_pkt + sizeof(struct esp_header);
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
