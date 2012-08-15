#include "base64.h"

#include <assert.h>
#include <strings.h>

static const char b64_map[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char pkt_buffer[SNAP_LEN*4/3 + 3];

void base64_enc_block(uint8_t in[3], char out[4], int len)
{
	unsigned int bin;

	assert(len >= 1 && len <= 3);

	if (len == 3) {
		bin = (in[0] << 16) + (in[1] << 8) + (in[2]);
		out[3] = b64_map[(bin >> 0) & 0x3f];
		out[2] = b64_map[(bin >> 6) & 0x3f];
		out[1] = b64_map[(bin >> 12) & 0x3f];
		out[0] = b64_map[(bin >> 18) & 0x3f];
	} else if (len == 2) {
		bin = (in[0] << 16) + (in[1] << 8);
		out[3] = '=';
		out[2] = b64_map[(bin >> 6) & 0x3f];
		out[1] = b64_map[(bin >> 12) & 0x3f];
		out[0] = b64_map[(bin >> 18) & 0x3f];
	} else if (len == 1) {
		bin = (in[0] << 16);
		out[3] = '=';
		out[2] = '=';
		out[1] = b64_map[(bin >> 12) & 0x3f];
		out[0] = b64_map[(bin >> 18) & 0x3f];
	}
}

void base64_encode(uint8_t *src, char *dst, int ssize, int dsize)
{
	int i;
	int len;

	assert(dsize >= (ssize + (ssize % 3)) * 4 / 3);

	for (i = 0; i < ssize; i = i + 3) {
		len = (ssize - i >= 3 ? 3 : ssize - i);
		base64_enc_block(src + i, dst + i * 4 / 3, len);
	}
}

char *base64_encode_packet(struct pkt *p)
{
	bzero(pkt_buffer, sizeof(pkt_buffer));

	base64_encode(p->raw_packet, pkt_buffer, p->pcap_header->len,
		sizeof(pkt_buffer));
	
	return pkt_buffer;
}

