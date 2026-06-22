/*
 *  WOFMNT
 *  Copyright (C) 2026  a1ive <https://github.com/a1ive/wofmnt>
 *
 *  WOFMNT is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  WOFMNT is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with WOFMNT.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Minimal WIM XPRESS/LZX chunk decompressors.
 *
 * The algorithms are adapted from the wimboot and wimlib.
 */

#include "wim_decompress.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HUFFMAN_BITS 16u
#define HUFFMAN_QL_BITS 7u
#define HUFFMAN_QL_SHIFT (HUFFMAN_BITS - HUFFMAN_QL_BITS)

typedef uint16_t HUFFMAN_RAW_SYMBOL;

typedef struct HUFFMAN_SYMBOLS
{
	uint8_t bits;
	uint8_t shift;
	uint16_t freq;
	uint32_t start;
	HUFFMAN_RAW_SYMBOL *raw;
} HUFFMAN_SYMBOLS;

typedef struct HUFFMAN_ALPHABET
{
	HUFFMAN_SYMBOLS huf[HUFFMAN_BITS];
	uint8_t lookup[1u << HUFFMAN_QL_BITS];
	HUFFMAN_RAW_SYMBOL *raw;
} HUFFMAN_ALPHABET;

static unsigned int huffman_len(HUFFMAN_SYMBOLS *sym)
{
	return sym->bits;
}

static HUFFMAN_RAW_SYMBOL huffman_raw(HUFFMAN_SYMBOLS *sym, unsigned int huf)
{
	return sym->raw[huf >> sym->shift];
}

static int huffman_alphabet(HUFFMAN_ALPHABET *alphabet, uint8_t *lengths, unsigned int count)
{
	HUFFMAN_SYMBOLS *sym;
	unsigned int huf;
	unsigned int cum_freq;
	unsigned int bits;
	unsigned int raw;
	unsigned int adjustment;
	unsigned int prefix;
	bool empty = true;
	bool complete;

	if (!alphabet->raw)
	{
		return -1;
	}
	memset(alphabet->huf, 0, sizeof(alphabet->huf));
	memset(alphabet->lookup, 0, sizeof(alphabet->lookup));

	for (raw = 0; raw < count; raw++)
	{
		bits = lengths[raw];
		if (bits)
		{
			if (bits > HUFFMAN_BITS)
			{
				return -1;
			}
			alphabet->huf[bits - 1u].freq++;
			empty = false;
		}
	}

	if (empty)
	{
		alphabet->huf[0].freq = 2;
	}

	huf = 0;
	cum_freq = 0;
	for (bits = 1; bits <= HUFFMAN_BITS; bits++)
	{
		sym = &alphabet->huf[bits - 1u];
		sym->bits = (uint8_t)bits;
		sym->shift = (uint8_t)(HUFFMAN_BITS - bits);
		sym->start = huf << sym->shift;
		sym->raw = &alphabet->raw[cum_freq];
		huf += sym->freq;
		if (huf > (1u << bits))
		{
			return -1;
		}
		huf <<= 1;
		cum_freq += sym->freq;
	}
	complete = (huf == (1u << bits));

	for (raw = 0; raw < count; raw++)
	{
		bits = lengths[raw];
		if (bits)
		{
			sym = &alphabet->huf[bits - 1u];
			*(sym->raw++) = (HUFFMAN_RAW_SYMBOL)raw;
		}
	}

	for (bits = 1; bits <= HUFFMAN_BITS; bits++)
	{
		sym = &alphabet->huf[bits - 1u];
		sym->raw -= sym->freq;
		adjustment = sym->start >> sym->shift;
		sym->raw -= adjustment;

		for (prefix = (sym->start >> HUFFMAN_QL_SHIFT);
			 prefix < (1u << HUFFMAN_QL_BITS);
			 prefix++)
		{
			alphabet->lookup[prefix] = (uint8_t)(bits - 1u);
		}
	}

	return complete ? 0 : -1;
}

static HUFFMAN_SYMBOLS *huffman_sym(HUFFMAN_ALPHABET *alphabet, unsigned int huf)
{
	unsigned int lookup_index = huf >> HUFFMAN_QL_SHIFT;
	HUFFMAN_SYMBOLS *sym = &alphabet->huf[alphabet->lookup[lookup_index]];

	while (sym > alphabet->huf && huf < sym->start)
	{
		sym--;
	}
	return sym;
}

static uint16_t read_u16le_unaligned(const void *p)
{
	uint16_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static int32_t read_i32le_unaligned(const void *p)
{
	int32_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static void write_i32le_unaligned(void *p, int32_t v)
{
	memcpy(p, &v, sizeof(v));
}

#define XCA_CODES 512u
#define XCA_END_MARKER 256u
#define XCA_BLOCK_SIZE (64u * 1024u)

typedef struct XCA
{
	HUFFMAN_ALPHABET alphabet;
	HUFFMAN_RAW_SYMBOL raw[XCA_CODES];
	uint8_t lengths[XCA_CODES];
} XCA;

static unsigned int xca_huf_len(const uint8_t nibbles[XCA_CODES / 2u], unsigned int symbol)
{
	return (nibbles[symbol / 2u] >> (4u * (symbol % 2u))) & 0x0fu;
}

static uint16_t xca_get16(const uint8_t **src)
{
	uint16_t v = read_u16le_unaligned(*src);
	*src += sizeof(v);
	return v;
}

static uint16_t xca_get16_zero_padded(const uint8_t **src, const uint8_t *end)
{
	if ((size_t)(end - *src) < sizeof(uint16_t))
	{
		return 0;
	}
	return xca_get16(src);
}

static uint8_t xca_get8_zero_padded(const uint8_t **src, const uint8_t *end)
{
	uint8_t v;
	if (*src >= end)
	{
		return 0;
	}
	v = **src;
	*src += 1;
	return v;
}

int wof_wim_xpress_decompress(
	const void *compressed_data,
	size_t compressed_size,
	void *uncompressed_data,
	size_t uncompressed_size)
{
	const uint8_t *src = (const uint8_t *)compressed_data;
	const uint8_t *end = src + compressed_size;
	uint8_t *out = (uint8_t *)uncompressed_data;
	size_t out_len = 0;
	size_t out_len_threshold = 0;
	XCA xca;
	uint32_t accum = 0;
	int extra_bits = 0;

	memset(&xca, 0, sizeof(xca));
	xca.alphabet.raw = xca.raw;

	while (out_len < uncompressed_size)
	{
		if (out_len >= out_len_threshold)
		{
			if ((size_t)(end - src) < XCA_CODES / 2u)
			{
				return -1;
			}
			for (unsigned int raw = 0; raw < XCA_CODES; raw++)
			{
				xca.lengths[raw] = (uint8_t)xca_huf_len(src, raw);
			}
			src += XCA_CODES / 2u;
			if (huffman_alphabet(&xca.alphabet, xca.lengths, XCA_CODES) != 0)
			{
				return -1;
			}
			accum = ((uint32_t)xca_get16_zero_padded(&src, end) << 16) | xca_get16_zero_padded(&src, end);
			extra_bits = 16;
			out_len_threshold = out_len + XCA_BLOCK_SIZE;
		}

		{
			unsigned int huf = accum >> (32u - HUFFMAN_BITS);
			HUFFMAN_SYMBOLS *sym = huffman_sym(&xca.alphabet, huf);
			unsigned int raw = huffman_raw(sym, huf);
			unsigned int len = huffman_len(sym);

			accum <<= len;
			extra_bits -= (int)len;
			if (extra_bits < 0)
			{
				accum |= (uint32_t)xca_get16_zero_padded(&src, end) << (-extra_bits);
				extra_bits += 16;
			}

			if (raw < XCA_END_MARKER)
			{
				if (out_len >= uncompressed_size)
				{
					return -1;
				}
				out[out_len++] = (uint8_t)raw;
			}
			else
			{
				unsigned int match_offset_bits;
				unsigned int match_len;
				unsigned int match_offset;
				const uint8_t *copy;

				raw -= XCA_END_MARKER;
				match_offset_bits = raw >> 4;
				match_len = raw & 0x0f;
				if (match_len == 0x0f)
				{
					match_len = xca_get8_zero_padded(&src, end);
					if (match_len == 0xff)
					{
						match_len = xca_get16_zero_padded(&src, end);
					}
					else
					{
						match_len += 0x0f;
					}
				}
				match_len += 3;
				if (match_offset_bits)
				{
					match_offset = (accum >> (32u - match_offset_bits)) + (1u << match_offset_bits);
				}
				else
				{
					match_offset = 1;
				}
				accum <<= match_offset_bits;
				extra_bits -= (int)match_offset_bits;
				if (extra_bits < 0)
				{
					accum |= (uint32_t)xca_get16_zero_padded(&src, end) << (-extra_bits);
					extra_bits += 16;
				}
				if (match_offset > out_len || match_len > uncompressed_size - out_len)
				{
					return -1;
				}
				copy = out + out_len - match_offset;
				while (match_len--)
				{
					out[out_len++] = *copy++;
				}
			}
		}
	}

	return out_len == uncompressed_size ? 0 : -1;
}

#define LZX_ALIGNOFFSET_CODES 8u
#define LZX_ALIGNOFFSET_BITS 3u
#define LZX_PRETREE_CODES 20u
#define LZX_PRETREE_BITS 4u
#define LZX_MAIN_LIT_CODES 256u
#define LZX_POSITION_SLOTS 30u
#define LZX_MAIN_CODES (LZX_MAIN_LIT_CODES + (8u * LZX_POSITION_SLOTS))
#define LZX_LENGTH_CODES 249u
#define LZX_BLOCK_TYPE_BITS 3u
#define LZX_DEFAULT_BLOCK_LEN 32768u
#define LZX_REPEATED_OFFSETS 3u
#define LZX_WIM_MAGIC_FILESIZE 12000000

typedef enum LZX_BLOCK_TYPE
{
	LZX_BLOCK_VERBATIM = 1,
	LZX_BLOCK_ALIGNOFFSET = 2,
	LZX_BLOCK_UNCOMPRESSED = 3
} LZX_BLOCK_TYPE;

typedef struct LZX_INPUT_STREAM
{
	const uint8_t *data;
	size_t len;
	size_t offset;
} LZX_INPUT_STREAM;

typedef struct LZX_OUTPUT_STREAM
{
	uint8_t *data;
	size_t len;
	size_t offset;
	size_t threshold;
} LZX_OUTPUT_STREAM;

typedef struct LZX
{
	LZX_INPUT_STREAM input;
	LZX_OUTPUT_STREAM output;
	uint32_t accumulator;
	unsigned int bits;
	LZX_BLOCK_TYPE block_type;
	unsigned int repeated_offset[LZX_REPEATED_OFFSETS];

	HUFFMAN_ALPHABET alignoffset;
	HUFFMAN_RAW_SYMBOL alignoffset_raw[LZX_ALIGNOFFSET_CODES];
	uint8_t alignoffset_lengths[LZX_ALIGNOFFSET_CODES];

	HUFFMAN_ALPHABET pretree;
	HUFFMAN_RAW_SYMBOL pretree_raw[LZX_PRETREE_CODES];
	uint8_t pretree_lengths[LZX_PRETREE_CODES];

	HUFFMAN_ALPHABET main;
	HUFFMAN_RAW_SYMBOL main_raw[LZX_MAIN_CODES];
	struct
	{
		uint8_t literals[LZX_MAIN_LIT_CODES];
		uint8_t remainder[LZX_MAIN_CODES - LZX_MAIN_LIT_CODES];
	} main_lengths;

	HUFFMAN_ALPHABET length;
	HUFFMAN_RAW_SYMBOL length_raw[LZX_LENGTH_CODES];
	uint8_t length_lengths[LZX_LENGTH_CODES];
} LZX;

static unsigned int lzx_position_base[LZX_POSITION_SLOTS];

static unsigned int lzx_footer_bits(unsigned int position_slot)
{
	if (position_slot < 2u)
	{
		return 0;
	}
	if (position_slot < 38u)
	{
		return (position_slot / 2u) - 1u;
	}
	return 17u;
}

static int lzx_accumulate(LZX *lzx, unsigned int bits)
{
	if (lzx->bits < bits && lzx->input.offset < lzx->input.len)
	{
		uint16_t src16;
		if (lzx->input.len - lzx->input.offset < sizeof(src16))
		{
			return -1;
		}
		src16 = read_u16le_unaligned(lzx->input.data + lzx->input.offset);
		lzx->input.offset += sizeof(src16);
		lzx->accumulator |= (uint32_t)src16 << (16u - lzx->bits);
		lzx->bits += 16u;
	}
	return (int)(lzx->accumulator >> 16);
}

static int lzx_consume(LZX *lzx, unsigned int bits)
{
	if (lzx->bits < bits)
	{
		return -1;
	}
	lzx->accumulator <<= bits;
	lzx->bits -= bits;
	return 0;
}

static int lzx_getbits(LZX *lzx, unsigned int bits)
{
	int norm_value = lzx_accumulate(lzx, bits);
	if (norm_value < 0)
	{
		return norm_value;
	}
	if (lzx_consume(lzx, bits) != 0)
	{
		return -1;
	}
	return norm_value >> (16u - bits);
}

static int lzx_align(LZX *lzx, unsigned int bits)
{
	if (lzx_getbits(lzx, bits) < 0)
	{
		return -1;
	}
	return lzx_consume(lzx, lzx->bits);
}

static int lzx_getbytes(LZX *lzx, void *data, size_t len)
{
	if (lzx->input.offset > lzx->input.len || len > lzx->input.len - lzx->input.offset)
	{
		return -1;
	}
	if (data)
	{
		memcpy(data, lzx->input.data + lzx->input.offset, len);
	}
	lzx->input.offset += len;
	return 0;
}

static int lzx_decode(LZX *lzx, HUFFMAN_ALPHABET *alphabet)
{
	int huf = lzx_accumulate(lzx, HUFFMAN_BITS);
	HUFFMAN_SYMBOLS *sym;
	if (huf < 0)
	{
		return huf;
	}
	sym = huffman_sym(alphabet, (unsigned int)huf);
	if (lzx_consume(lzx, huffman_len(sym)) != 0)
	{
		return -1;
	}
	return huffman_raw(sym, (unsigned int)huf);
}

static int lzx_raw_alphabet(LZX *lzx, unsigned int count, unsigned int bits, uint8_t *lengths, HUFFMAN_ALPHABET *alphabet)
{
	for (unsigned int i = 0; i < count; i++)
	{
		int len = lzx_getbits(lzx, bits);
		if (len < 0)
		{
			return len;
		}
		lengths[i] = (uint8_t)len;
	}
	return huffman_alphabet(alphabet, lengths, count);
}

static int lzx_pretree(LZX *lzx, unsigned int count, uint8_t *lengths)
{
	unsigned int length = 0;
	int dup = 0;
	int code;

	if (lzx_raw_alphabet(lzx, LZX_PRETREE_CODES, LZX_PRETREE_BITS, lzx->pretree_lengths, &lzx->pretree) != 0)
	{
		return -1;
	}

	for (unsigned int i = 0; i < count; i++)
	{
		if (dup)
		{
			lengths[i] = lengths[i - 1u];
			dup--;
		}
		else
		{
			code = lzx_decode(lzx, &lzx->pretree);
			if (code < 0)
			{
				return code;
			}
			if (code <= 16)
			{
				length = (unsigned int)((lengths[i] - code + 17) % 17);
			}
			else if (code == 17)
			{
				length = 0;
				dup = lzx_getbits(lzx, 4);
				if (dup < 0)
				{
					return dup;
				}
				dup += 3;
			}
			else if (code == 18)
			{
				length = 0;
				dup = lzx_getbits(lzx, 5);
				if (dup < 0)
				{
					return dup;
				}
				dup += 19;
			}
			else if (code == 19)
			{
				length = 0;
				dup = lzx_getbits(lzx, 1);
				if (dup < 0)
				{
					return dup;
				}
				dup += 3;
				code = lzx_decode(lzx, &lzx->pretree);
				if (code < 0)
				{
					return code;
				}
				length = (unsigned int)((lengths[i] - code + 17) % 17);
			}
			else
			{
				return -1;
			}
			lengths[i] = (uint8_t)length;
		}
	}
	return dup ? -1 : 0;
}

static int lzx_alignoffset_alphabet(LZX *lzx)
{
	return lzx_raw_alphabet(lzx, LZX_ALIGNOFFSET_CODES, LZX_ALIGNOFFSET_BITS, lzx->alignoffset_lengths, &lzx->alignoffset);
}

static int lzx_main_alphabet(LZX *lzx)
{
	if (lzx_pretree(lzx, LZX_MAIN_LIT_CODES, lzx->main_lengths.literals) != 0)
	{
		return -1;
	}
	if (lzx_pretree(lzx, LZX_MAIN_CODES - LZX_MAIN_LIT_CODES, lzx->main_lengths.remainder) != 0)
	{
		return -1;
	}
	return huffman_alphabet(&lzx->main, lzx->main_lengths.literals, LZX_MAIN_CODES);
}

static int lzx_length_alphabet(LZX *lzx)
{
	if (lzx_pretree(lzx, LZX_LENGTH_CODES, lzx->length_lengths) != 0)
	{
		return -1;
	}
	return huffman_alphabet(&lzx->length, lzx->length_lengths, LZX_LENGTH_CODES);
}

static int lzx_block_header(LZX *lzx)
{
	size_t block_len;
	int block_type = lzx_getbits(lzx, LZX_BLOCK_TYPE_BITS);
	int default_len;
	int len_high;
	int len_low;

	if (block_type < 0)
	{
		return block_type;
	}
	lzx->block_type = (LZX_BLOCK_TYPE)block_type;

	default_len = lzx_getbits(lzx, 1);
	if (default_len < 0)
	{
		return default_len;
	}
	if (default_len)
	{
		block_len = LZX_DEFAULT_BLOCK_LEN;
	}
	else
	{
		len_high = lzx_getbits(lzx, 8);
		len_low = lzx_getbits(lzx, 8);
		if (len_high < 0 || len_low < 0)
		{
			return -1;
		}
		block_len = (size_t)((len_high << 8) | len_low);
	}
	if (block_len > lzx->output.len - lzx->output.offset)
	{
		return -1;
	}
	lzx->output.threshold = lzx->output.offset + block_len;

	switch (lzx->block_type)
	{
	case LZX_BLOCK_ALIGNOFFSET:
		if (lzx_alignoffset_alphabet(lzx) != 0)
		{
			return -1;
		}
		/* fall through */
	case LZX_BLOCK_VERBATIM:
		if (lzx_main_alphabet(lzx) != 0)
		{
			return -1;
		}
		if (lzx_length_alphabet(lzx) != 0)
		{
			return -1;
		}
		break;
	case LZX_BLOCK_UNCOMPRESSED:
		if (lzx_align(lzx, 1) != 0)
		{
			return -1;
		}
		if (lzx_getbytes(lzx, &lzx->repeated_offset, sizeof(lzx->repeated_offset)) != 0)
		{
			return -1;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

static int lzx_uncompressed(LZX *lzx)
{
	size_t len = lzx->output.threshold - lzx->output.offset;
	void *data = lzx->output.data ? lzx->output.data + lzx->output.offset : NULL;

	if (lzx_getbytes(lzx, data, len) != 0)
	{
		return -1;
	}
	lzx->output.offset += len;
	if (len % 2u)
	{
		if (lzx->input.offset >= lzx->input.len)
		{
			return -1;
		}
		lzx->input.offset++;
	}
	return 0;
}

static int lzx_token(LZX *lzx)
{
	unsigned int length_header;
	unsigned int position_slot;
	unsigned int offset_bits;
	size_t match_offset;
	size_t match_length;
	int verbatim_bits;
	int aligned_bits;
	int main = lzx_decode(lzx, &lzx->main);
	int length;

	if (main < 0)
	{
		return main;
	}
	if (main < (int)LZX_MAIN_LIT_CODES)
	{
		if (lzx->output.offset >= lzx->output.len)
		{
			return -1;
		}
		lzx->output.data[lzx->output.offset++] = (uint8_t)main;
		return 0;
	}
	main -= LZX_MAIN_LIT_CODES;
	length_header = (unsigned int)main & 7u;
	if (length_header == 7u)
	{
		length = lzx_decode(lzx, &lzx->length);
		if (length < 0)
		{
			return length;
		}
	}
	else
	{
		length = 0;
	}
	match_length = length_header + 2u + (unsigned int)length;
	position_slot = (unsigned int)main >> 3;

	if (position_slot < LZX_REPEATED_OFFSETS)
	{
		match_offset = lzx->repeated_offset[position_slot];
		lzx->repeated_offset[position_slot] = lzx->repeated_offset[0];
		lzx->repeated_offset[0] = (unsigned int)match_offset;
	}
	else
	{
		offset_bits = lzx_footer_bits(position_slot);
		if (lzx->block_type == LZX_BLOCK_ALIGNOFFSET && offset_bits >= 3u)
		{
			verbatim_bits = lzx_getbits(lzx, offset_bits - 3u);
			if (verbatim_bits < 0)
			{
				return verbatim_bits;
			}
			verbatim_bits <<= 3;
			aligned_bits = lzx_decode(lzx, &lzx->alignoffset);
			if (aligned_bits < 0)
			{
				return aligned_bits;
			}
		}
		else
		{
			verbatim_bits = lzx_getbits(lzx, offset_bits);
			if (verbatim_bits < 0)
			{
				return verbatim_bits;
			}
			aligned_bits = 0;
		}
		match_offset = lzx_position_base[position_slot] + (unsigned int)verbatim_bits + (unsigned int)aligned_bits - 2u;
		for (unsigned int i = LZX_REPEATED_OFFSETS - 1u; i > 0; i--)
		{
			lzx->repeated_offset[i] = lzx->repeated_offset[i - 1u];
		}
		lzx->repeated_offset[0] = (unsigned int)match_offset;
	}

	if (match_offset > lzx->output.offset ||
		match_length > lzx->output.len - lzx->output.offset)
	{
		return -1;
	}
	{
		uint8_t *copy = &lzx->output.data[lzx->output.offset];
		for (size_t i = 0; i < match_length; i++)
		{
			copy[i] = copy[i - match_offset];
		}
	}
	lzx->output.offset += match_length;
	return 0;
}

static void lzx_translate_jumps(LZX *lzx)
{
	if (!lzx->output.data || lzx->output.offset < 10u)
	{
		return;
	}
	for (size_t offset = 0; offset < lzx->output.offset - 10u; offset++)
	{
		int32_t target;
		if (lzx->output.data[offset] != 0xe8)
		{
			continue;
		}
		target = read_i32le_unaligned(&lzx->output.data[offset + 1u]);
		if (target >= 0)
		{
			if (target < LZX_WIM_MAGIC_FILESIZE)
			{
				target -= (int32_t)offset;
			}
		}
		else if (target >= -((int32_t)offset))
		{
			target += LZX_WIM_MAGIC_FILESIZE;
		}
		write_i32le_unaligned(&lzx->output.data[offset + 1u], target);
		offset += sizeof(target);
	}
}

int wof_wim_lzx_decompress(
	const void *compressed_data,
	size_t compressed_size,
	void *uncompressed_data,
	size_t uncompressed_size)
{
	LZX lzx;

	if ((compressed_size & 1u) != 0)
	{
		return -1;
	}
	if (!lzx_position_base[LZX_POSITION_SLOTS - 1u])
	{
		for (unsigned int i = 1; i < LZX_POSITION_SLOTS; i++)
		{
			lzx_position_base[i] = lzx_position_base[i - 1u] + (1u << lzx_footer_bits(i - 1u));
		}
	}

	memset(&lzx, 0, sizeof(lzx));
	lzx.alignoffset.raw = lzx.alignoffset_raw;
	lzx.pretree.raw = lzx.pretree_raw;
	lzx.main.raw = lzx.main_raw;
	lzx.length.raw = lzx.length_raw;
	lzx.input.data = (const uint8_t *)compressed_data;
	lzx.input.len = compressed_size;
	lzx.output.data = (uint8_t *)uncompressed_data;
	lzx.output.len = uncompressed_size;
	for (unsigned int i = 0; i < LZX_REPEATED_OFFSETS; i++)
	{
		lzx.repeated_offset[i] = 1;
	}

	while (lzx.input.offset < lzx.input.len)
	{
		if (lzx_block_header(&lzx) != 0)
		{
			return -1;
		}
		if (lzx.block_type == LZX_BLOCK_UNCOMPRESSED)
		{
			if (lzx_uncompressed(&lzx) != 0)
			{
				return -1;
			}
		}
		else
		{
			while (lzx.output.offset < lzx.output.threshold)
			{
				if (lzx_token(&lzx) != 0)
				{
					return -1;
				}
			}
		}
	}
	if (lzx.output.offset != uncompressed_size)
	{
		return -1;
	}
	lzx_translate_jumps(&lzx);
	return 0;
}
