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

#pragma once

#include <stddef.h>
#include <stdint.h>

int wof_wim_lzx_decompress(
	const void *compressed_data,
	size_t compressed_size,
	void *uncompressed_data,
	size_t uncompressed_size);

int wof_wim_xpress_decompress(
	const void *compressed_data,
	size_t compressed_size,
	void *uncompressed_data,
	size_t uncompressed_size);
