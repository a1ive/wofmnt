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

#include "woflib.h"
#include "wim_decompress.h"

#include <AclAPI.h>
#include <winioctl.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef WIM_PROVIDER_HASH_SIZE
#define WIM_PROVIDER_HASH_SIZE 20
#endif

#ifndef WIM_PROVIDER_CURRENT_VERSION
#define WIM_PROVIDER_CURRENT_VERSION 1
#endif

#ifndef WOF_CURRENT_VERSION
#define WOF_CURRENT_VERSION 1
#endif

#ifndef WOF_PROVIDER_WIM
#define WOF_PROVIDER_WIM 1
#endif

#ifndef FSCTL_SET_EXTERNAL_BACKING
#define FSCTL_SET_EXTERNAL_BACKING CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 195, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif

#ifndef FSCTL_DELETE_EXTERNAL_BACKING
#define FSCTL_DELETE_EXTERNAL_BACKING CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 197, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif

#ifndef FSCTL_ADD_OVERLAY
#define FSCTL_ADD_OVERLAY CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 204, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif

#ifndef FSCTL_REMOVE_OVERLAY
#define FSCTL_REMOVE_OVERLAY CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 205, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif

#ifndef WIM_BOOT_OS_WIM
#define WIM_BOOT_OS_WIM 1
#endif

#ifndef WIM_BOOT_NOT_OS_WIM
#define WIM_BOOT_NOT_OS_WIM 0
#endif

#ifndef IO_REPARSE_TAG_WOF
#define IO_REPARSE_TAG_WOF 0x80000017UL
#endif

#define WIM_SIGNATURE "MSWIM\0\0"
#define WIM_HDR_FLAG_XPRESS 0x00020000u
#define WIM_HDR_FLAG_LZX 0x00040000u
#define WIM_HDR_FLAG_LZMS 0x00080000u
#define WIM_DEFAULT_CHUNK_SIZE 32768u

#define WIM_RESHDR_ZLEN_MASK 0x00FFFFFFFFFFFFFFULL
#define WIM_RESHDR_FLAG_METADATA (0x02ULL << 56)
#define WIM_RESHDR_FLAG_COMPRESSED (0x04ULL << 56)
#define WIM_RESHDR_FLAG_PACKED_STREAMS (0x10ULL << 56)

#define WIM_NO_SECURITY_ID 0xFFFFFFFFu
#define REPARSE_POINT_MAX_SIZE 16384u
#define REPARSE_DATA_OFFSET 8u
#define MANIFEST_NAME L".wofmnt"
#define MANIFEST_MAGIC "WOFMNT1"
#define MANIFEST_VERSION 1u

#pragma pack(push, 1)
typedef struct WIM_RESOURCE_HEADER_DISK
{
	uint64_t zlen_flags;
	uint64_t offset;
	uint64_t length;
} WIM_RESOURCE_HEADER_DISK;

typedef struct WIM_HEADER_DISK
{
	BYTE signature[8];
	uint32_t header_size;
	uint32_t version;
	uint32_t flags;
	uint32_t chunk_size;
	BYTE guid[16];
	uint16_t part_number;
	uint16_t total_parts;
	uint32_t image_count;
	WIM_RESOURCE_HEADER_DISK lookup;
	WIM_RESOURCE_HEADER_DISK xml;
	WIM_RESOURCE_HEADER_DISK boot;
	uint32_t boot_index;
	WIM_RESOURCE_HEADER_DISK integrity;
	BYTE reserved[60];
} WIM_HEADER_DISK;

typedef struct WIM_LOOKUP_ENTRY_DISK
{
	WIM_RESOURCE_HEADER_DISK resource;
	uint16_t part_number;
	uint32_t ref_count;
	BYTE hash[WIM_PROVIDER_HASH_SIZE];
} WIM_LOOKUP_ENTRY_DISK;

typedef struct WIM_DENTRY_DISK
{
	uint64_t length;
	uint32_t attributes;
	uint32_t security_id;
	uint64_t subdir_offset;
	uint64_t unused_1;
	uint64_t unused_2;
	uint64_t creation_time;
	uint64_t last_access_time;
	uint64_t last_write_time;
	BYTE main_hash[WIM_PROVIDER_HASH_SIZE];
	uint32_t unknown_0x54;
	union
	{
		struct
		{
			uint32_t reparse_tag;
			uint16_t rp_reserved;
			uint16_t rp_flags;
		} reparse;
		uint64_t hard_link_group_id;
	} link;
	uint16_t num_extra_streams;
	uint16_t short_name_nbytes;
	uint16_t name_nbytes;
} WIM_DENTRY_DISK;

typedef struct WIM_STREAM_ENTRY_DISK
{
	uint64_t length;
	uint64_t reserved;
	BYTE hash[WIM_PROVIDER_HASH_SIZE];
	uint16_t name_nbytes;
} WIM_STREAM_ENTRY_DISK;

typedef struct WIM_SECURITY_HEADER_DISK
{
	uint32_t total_length;
	uint32_t num_entries;
} WIM_SECURITY_HEADER_DISK;

typedef struct REPARSE_BUFFER_HEADER_DISK
{
	uint32_t reparse_tag;
	uint16_t reparse_data_length;
	uint16_t reparse_reserved;
} REPARSE_BUFFER_HEADER_DISK;

typedef struct WOFMNT_MANIFEST_HEADER
{
	char magic[8];
	uint32_t version;
	uint32_t image_index;
	int64_t data_source_id;
	uint32_t wim_path_chars;
} WOFMNT_MANIFEST_HEADER;
#pragma pack(pop)

_Static_assert(sizeof(WIM_RESOURCE_HEADER_DISK) == 24, "WIM resource header size");
_Static_assert(sizeof(WIM_HEADER_DISK) == 208, "WIM header size");
_Static_assert(sizeof(WIM_LOOKUP_ENTRY_DISK) == 50, "WIM lookup entry size");
_Static_assert(sizeof(WIM_DENTRY_DISK) == 102, "WIM dentry size");

typedef HRESULT(WINAPI *FILTER_ATTACH_PROC)(
	LPCWSTR lpFilterName,
	LPCWSTR lpVolumeName,
	LPCWSTR lpInstanceName,
	DWORD dwCreatedInstanceNameLength,
	LPWSTR lpCreatedInstanceName);

typedef enum STREAM_KIND
{
	STREAM_KIND_UNKNOWN = 0,
	STREAM_KIND_DATA,
	STREAM_KIND_REPARSE,
	STREAM_KIND_EFS_RAW
} STREAM_KIND;

typedef struct WIM_RESOURCE
{
	uint64_t zlen_flags;
	uint64_t offset;
	uint64_t length;
} WIM_RESOURCE;

typedef struct WIM_LOOKUP_ITEM
{
	BYTE hash[WIM_PROVIDER_HASH_SIZE];
	WIM_RESOURCE resource;
	uint16_t part_number;
	uint32_t ref_count;
	bool is_metadata;
} WIM_LOOKUP_ITEM;

typedef struct WIM_STREAM
{
	STREAM_KIND kind;
	BYTE hash[WIM_PROVIDER_HASH_SIZE];
	wchar_t *name;
	uint64_t size;
	bool has_resource;
} WIM_STREAM;

typedef struct WIM_DENTRY
{
	uint32_t attributes;
	uint32_t security_id;
	uint64_t subdir_offset;
	uint64_t creation_time;
	uint64_t last_access_time;
	uint64_t last_write_time;
	uint32_t reparse_tag;
	uint16_t rp_reserved;
	uint16_t rp_flags;
	uint64_t hard_link_group_id;
	wchar_t *name;
	WIM_STREAM *streams;
	size_t num_streams;
} WIM_DENTRY;

typedef struct WIM_SECURITY_TABLE
{
	uint32_t total_length;
	uint32_t num_entries;
	uint64_t *sizes;
	BYTE **descriptors;
} WIM_SECURITY_TABLE;

typedef struct HARD_LINK_ENTRY
{
	uint64_t id;
	wchar_t *first_path;
} HARD_LINK_ENTRY;

typedef struct HARD_LINK_TABLE
{
	HARD_LINK_ENTRY *entries;
	size_t count;
	size_t capacity;
} HARD_LINK_TABLE;

typedef struct WIM_FILE
{
	HANDLE handle;
	uint64_t file_size;
	WIM_HEADER_DISK header;
	WIM_LOOKUP_ITEM *lookup;
	size_t lookup_count;
	WIM_RESOURCE *metadata_resources;
	BYTE(*metadata_hashes)
	[WIM_PROVIDER_HASH_SIZE];
	size_t metadata_count;
} WIM_FILE;

typedef struct APPLY_CONTEXT
{
	WIM_FILE *wim;
	BYTE *metadata;
	size_t metadata_size;
	WIM_SECURITY_TABLE security;
	wchar_t *target_path;
	wchar_t *wim_path;
	uint32_t image_index;
	uint32_t flags;
	LARGE_INTEGER data_source_id;
	WOFMNT_PROGRESS_CALLBACK progress;
	void *progress_context;
	WOFMNT_MOUNT_STATS *stats;
	HARD_LINK_TABLE hard_links;
} APPLY_CONTEXT;

static size_t align8_size(size_t value)
{
	return (value + 7u) & ~(size_t)7u;
}

static uint64_t align8_u64(uint64_t value)
{
	return (value + 7u) & ~UINT64_C(7);
}

static bool hash_is_zero(const BYTE hash[WIM_PROVIDER_HASH_SIZE])
{
	BYTE accum = 0;
	for (size_t i = 0; i < WIM_PROVIDER_HASH_SIZE; ++i)
	{
		accum = (BYTE)(accum | hash[i]);
	}
	return accum == 0;
}

static void stats_warning(APPLY_CONTEXT *ctx)
{
	if (ctx && ctx->stats)
	{
		ctx->stats->warnings++;
	}
}

static void progress_event(APPLY_CONTEXT *ctx, WOFMNT_PROGRESS_EVENT event_id, const wchar_t *path, const wchar_t *detail)
{
	if (ctx && ctx->progress)
	{
		ctx->progress(event_id, path, detail, ctx->progress_context);
	}
	if (event_id == WOFMNT_PROGRESS_WARNING)
	{
		stats_warning(ctx);
	}
}

static DWORD last_error_or(DWORD fallback)
{
	DWORD err = GetLastError();
	return err == ERROR_SUCCESS ? fallback : err;
}

static bool checked_size_from_u64(uint64_t value, size_t *out)
{
	if (value > (uint64_t)SIZE_MAX)
	{
		return false;
	}
	*out = (size_t)value;
	return true;
}

static void *xcalloc(size_t count, size_t size)
{
	if (count != 0 && size > SIZE_MAX / count)
	{
		return NULL;
	}
	return calloc(count, size);
}

static wchar_t *xwcsdup(const wchar_t *s)
{
	size_t len;
	wchar_t *copy;

	if (!s)
	{
		return NULL;
	}
	len = wcslen(s);
	if (len > (SIZE_MAX / sizeof(wchar_t)) - 1u)
	{
		return NULL;
	}
	copy = (wchar_t *)calloc(len + 1u, sizeof(wchar_t));
	if (!copy)
	{
		return NULL;
	}
	memcpy(copy, s, (len + 1u) * sizeof(wchar_t));
	return copy;
}

static wchar_t *make_full_path_no_prefix(const wchar_t *path)
{
	DWORD needed;
	wchar_t *buffer;
	DWORD written;

	needed = GetFullPathNameW(path, 0, NULL, NULL);
	if (needed == 0)
	{
		return NULL;
	}
	buffer = (wchar_t *)calloc((size_t)needed + 1u, sizeof(wchar_t));
	if (!buffer)
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}
	written = GetFullPathNameW(path, needed, buffer, NULL);
	if (written == 0 || written >= needed)
	{
		free(buffer);
		return NULL;
	}
	return buffer;
}

static wchar_t *make_extended_path_from_full(const wchar_t *full_path)
{
	static const wchar_t prefix[] = L"\\\\?\\";
	size_t prefix_len = 4u;
	size_t path_len = wcslen(full_path);
	wchar_t *out;

	if (wcsncmp(full_path, prefix, prefix_len) == 0)
	{
		return xwcsdup(full_path);
	}

	if (path_len >= 2u && full_path[0] == L'\\' && full_path[1] == L'\\')
	{
		static const wchar_t unc_prefix[] = L"\\\\?\\UNC\\";
		size_t unc_prefix_len = 8u;
		if (path_len > (SIZE_MAX / sizeof(wchar_t)) - unc_prefix_len - 1u)
		{
			SetLastError(ERROR_OUTOFMEMORY);
			return NULL;
		}
		out = (wchar_t *)calloc(unc_prefix_len + path_len - 1u, sizeof(wchar_t));
		if (!out)
		{
			SetLastError(ERROR_OUTOFMEMORY);
			return NULL;
		}
		memcpy(out, unc_prefix, unc_prefix_len * sizeof(wchar_t));
		memcpy(out + unc_prefix_len, full_path + 2, (path_len - 1u) * sizeof(wchar_t));
		return out;
	}

	if (path_len > (SIZE_MAX / sizeof(wchar_t)) - prefix_len - 1u)
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}
	out = (wchar_t *)calloc(prefix_len + path_len + 1u, sizeof(wchar_t));
	if (!out)
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}
	memcpy(out, prefix, prefix_len * sizeof(wchar_t));
	memcpy(out + prefix_len, full_path, (path_len + 1u) * sizeof(wchar_t));
	return out;
}

static wchar_t *normalize_path_for_io(const wchar_t *path)
{
	wchar_t *full_path = make_full_path_no_prefix(path);
	wchar_t *extended_path;

	if (!full_path)
	{
		return NULL;
	}
	extended_path = make_extended_path_from_full(full_path);
	free(full_path);
	return extended_path;
}

static wchar_t *make_child_path(const wchar_t *parent, const wchar_t *name)
{
	size_t parent_len = wcslen(parent);
	size_t name_len = wcslen(name);
	bool need_slash = parent_len != 0 && parent[parent_len - 1u] != L'\\';
	size_t total_len;
	wchar_t *out;

	if (name_len == 0 || wcschr(name, L'\\') || wcschr(name, L'/') || wcschr(name, L':'))
	{
		SetLastError(ERROR_INVALID_NAME);
		return NULL;
	}

	if (parent_len > SIZE_MAX - name_len - (need_slash ? 2u : 1u))
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}
	total_len = parent_len + name_len + (need_slash ? 1u : 0u);
	out = (wchar_t *)calloc(total_len + 1u, sizeof(wchar_t));
	if (!out)
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}
	memcpy(out, parent, parent_len * sizeof(wchar_t));
	if (need_slash)
	{
		out[parent_len++] = L'\\';
	}
	memcpy(out + parent_len, name, (name_len + 1u) * sizeof(wchar_t));
	return out;
}

static wchar_t *make_stream_path(const wchar_t *path, const wchar_t *stream_name)
{
	size_t path_len = wcslen(path);
	size_t stream_len = wcslen(stream_name);
	wchar_t *out;

	if (stream_len == 0 || wcschr(stream_name, L'\\') || wcschr(stream_name, L'/') || wcschr(stream_name, L':'))
	{
		SetLastError(ERROR_INVALID_NAME);
		return NULL;
	}
	if (path_len > SIZE_MAX - stream_len - 2u)
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}
	out = (wchar_t *)calloc(path_len + stream_len + 2u, sizeof(wchar_t));
	if (!out)
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}
	memcpy(out, path, path_len * sizeof(wchar_t));
	out[path_len] = L':';
	memcpy(out + path_len + 1u, stream_name, (stream_len + 1u) * sizeof(wchar_t));
	return out;
}

static DWORD get_drive_device_path(const wchar_t *path, wchar_t drive_path[7])
{
	wchar_t *full_path = make_full_path_no_prefix(path);

	if (!full_path)
	{
		return last_error_or(ERROR_INVALID_PARAMETER);
	}
	if (wcslen(full_path) < 2u || full_path[1] != L':' || full_path[0] == L'\0')
	{
		free(full_path);
		return ERROR_NOT_SUPPORTED;
	}
	drive_path[0] = L'\\';
	drive_path[1] = L'\\';
	drive_path[2] = L'.';
	drive_path[3] = L'\\';
	drive_path[4] = full_path[0];
	drive_path[5] = L':';
	drive_path[6] = L'\0';
	free(full_path);
	return ERROR_SUCCESS;
}

static DWORD enable_privilege(const wchar_t *privilege_name)
{
	HANDLE token = NULL;
	TOKEN_PRIVILEGES privileges;
	LUID luid;
	DWORD err = ERROR_SUCCESS;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
	{
		return last_error_or(ERROR_ACCESS_DENIED);
	}
	if (!LookupPrivilegeValueW(NULL, privilege_name, &luid))
	{
		err = last_error_or(ERROR_PRIVILEGE_NOT_HELD);
		CloseHandle(token);
		return err;
	}

	ZeroMemory(&privileges, sizeof(privileges));
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	SetLastError(ERROR_SUCCESS);
	if (!AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL))
	{
		err = last_error_or(ERROR_PRIVILEGE_NOT_HELD);
	}
	else if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		err = ERROR_PRIVILEGE_NOT_HELD;
	}
	CloseHandle(token);
	return err;
}

static void enable_best_effort_privileges(void)
{
	(void)enable_privilege(SE_BACKUP_NAME);
	(void)enable_privilege(SE_RESTORE_NAME);
	(void)enable_privilege(SE_SECURITY_NAME);
	(void)enable_privilege(SE_TAKE_OWNERSHIP_NAME);
	(void)enable_privilege(SE_MANAGE_VOLUME_NAME);
	(void)enable_privilege(SE_CREATE_SYMBOLIC_LINK_NAME);
}

static bool is_directory_empty(const wchar_t *target_path)
{
	wchar_t *pattern = make_child_path(target_path, L"*");
	WIN32_FIND_DATAW data;
	HANDLE find_handle;
	bool empty = true;

	if (!pattern)
	{
		return false;
	}
	find_handle = FindFirstFileW(pattern, &data);
	free(pattern);
	if (find_handle == INVALID_HANDLE_VALUE)
	{
		return GetLastError() == ERROR_FILE_NOT_FOUND;
	}
	do
	{
		if (wcscmp(data.cFileName, L".") != 0 && wcscmp(data.cFileName, L"..") != 0)
		{
			empty = false;
			break;
		}
	} while (FindNextFileW(find_handle, &data));
	FindClose(find_handle);
	return empty;
}

static DWORD validate_target_directory(const wchar_t *target_path)
{
	DWORD attributes = GetFileAttributesW(target_path);
	wchar_t root[MAX_PATH];
	wchar_t fs_name[MAX_PATH];

	if (attributes == INVALID_FILE_ATTRIBUTES)
	{
		return last_error_or(ERROR_PATH_NOT_FOUND);
	}
	if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
	{
		return ERROR_DIRECTORY;
	}
	if (!GetVolumePathNameW(target_path, root, ARRAYSIZE(root)))
	{
		return last_error_or(ERROR_INVALID_DRIVE);
	}
	if (!GetVolumeInformationW(root, NULL, 0, NULL, NULL, NULL, fs_name, ARRAYSIZE(fs_name)))
	{
		return last_error_or(ERROR_INVALID_DRIVE);
	}
	if (_wcsicmp(fs_name, L"NTFS") != 0)
	{
		return ERROR_NOT_SUPPORTED;
	}
	if (!is_directory_empty(target_path))
	{
		return ERROR_DIR_NOT_EMPTY;
	}
	return ERROR_SUCCESS;
}

static DWORD try_attach_wof(const wchar_t *drive_without_prefix)
{
	HMODULE fltlib = LoadLibraryW(L"Fltlib.dll");
	FILTER_ATTACH_PROC filter_attach;
	HRESULT hr;

	if (!fltlib)
	{
		return last_error_or(ERROR_MOD_NOT_FOUND);
	}
	filter_attach = (FILTER_ATTACH_PROC)GetProcAddress(fltlib, "FilterAttach");
	if (!filter_attach)
	{
		FreeLibrary(fltlib);
		return ERROR_PROC_NOT_FOUND;
	}
	hr = filter_attach(L"wof", drive_without_prefix, NULL, 0, NULL);
	if (hr != S_OK)
	{
		hr = filter_attach(L"wofadk", drive_without_prefix, NULL, 0, NULL);
	}
	FreeLibrary(fltlib);
	return hr == S_OK ? ERROR_SUCCESS : HRESULT_CODE(hr);
}

static DWORD read_exact_at(HANDLE file, uint64_t offset, void *buffer, size_t size)
{
	LARGE_INTEGER li;
	BYTE *out = (BYTE *)buffer;
	size_t remaining = size;

	li.QuadPart = (LONGLONG)offset;
	if (!SetFilePointerEx(file, li, NULL, FILE_BEGIN))
	{
		return last_error_or(ERROR_READ_FAULT);
	}
	while (remaining != 0)
	{
		DWORD chunk = remaining > UINT32_MAX ? UINT32_MAX : (DWORD)remaining;
		DWORD bytes_read = 0;
		if (!ReadFile(file, out, chunk, &bytes_read, NULL))
		{
			return last_error_or(ERROR_READ_FAULT);
		}
		if (bytes_read == 0)
		{
			return ERROR_HANDLE_EOF;
		}
		out += bytes_read;
		remaining -= bytes_read;
	}
	return ERROR_SUCCESS;
}

static DWORD write_exact(HANDLE file, const void *buffer, size_t size)
{
	const BYTE *in = (const BYTE *)buffer;
	size_t remaining = size;

	while (remaining != 0)
	{
		DWORD chunk = remaining > UINT32_MAX ? UINT32_MAX : (DWORD)remaining;
		DWORD bytes_written = 0;
		if (!WriteFile(file, in, chunk, &bytes_written, NULL))
		{
			return last_error_or(ERROR_WRITE_FAULT);
		}
		if (bytes_written == 0)
		{
			return ERROR_WRITE_FAULT;
		}
		in += bytes_written;
		remaining -= bytes_written;
	}
	return ERROR_SUCCESS;
}

static DWORD wim_decompress_chunk(
	WIM_FILE *wim,
	BYTE *compressed,
	size_t compressed_size,
	BYTE *uncompressed,
	size_t expected_size)
{
	(void)wim;
	if ((wim->header.flags & WIM_HDR_FLAG_LZX) != 0)
	{
		return wof_wim_lzx_decompress(compressed, compressed_size, uncompressed, expected_size) == 0
				   ? ERROR_SUCCESS
				   : ERROR_INVALID_DATA;
	}
	if ((wim->header.flags & WIM_HDR_FLAG_XPRESS) != 0)
	{
		return wof_wim_xpress_decompress(compressed, compressed_size, uncompressed, expected_size) == 0
				   ? ERROR_SUCCESS
				   : ERROR_INVALID_DATA;
	}
	return ERROR_NOT_SUPPORTED;
}

static DWORD wim_chunk_offset(WIM_FILE *wim, const WIM_RESOURCE *resource, uint32_t chunk_index, uint64_t *chunk_offset)
{
	uint64_t zlen = resource->zlen_flags & WIM_RESHDR_ZLEN_MASK;
	uint32_t chunk_size = wim->header.chunk_size != 0 ? wim->header.chunk_size : WIM_DEFAULT_CHUNK_SIZE;
	uint64_t chunk_count;
	size_t offset_size;
	uint64_t table_size;
	DWORD err;

	if (resource->length == 0)
	{
		*chunk_offset = 0;
		return ERROR_SUCCESS;
	}
	chunk_count = (resource->length + chunk_size - 1u) / chunk_size;
	offset_size = resource->length > UINT32_MAX ? sizeof(uint64_t) : sizeof(uint32_t);
	table_size = (chunk_count - 1u) * offset_size;
	if (table_size > zlen)
	{
		return ERROR_INVALID_DATA;
	}
	if (chunk_index == 0)
	{
		*chunk_offset = table_size;
		return ERROR_SUCCESS;
	}
	if ((uint64_t)chunk_index >= chunk_count)
	{
		*chunk_offset = zlen;
		return ERROR_SUCCESS;
	}
	if (offset_size == sizeof(uint64_t))
	{
		uint64_t value = 0;
		err = read_exact_at(wim->handle, resource->offset + ((uint64_t)(chunk_index - 1u) * offset_size), &value, sizeof(value));
		if (err != ERROR_SUCCESS)
		{
			return err;
		}
		*chunk_offset = table_size + value;
	}
	else
	{
		uint32_t value = 0;
		err = read_exact_at(wim->handle, resource->offset + ((uint64_t)(chunk_index - 1u) * offset_size), &value, sizeof(value));
		if (err != ERROR_SUCCESS)
		{
			return err;
		}
		*chunk_offset = table_size + value;
	}
	if (*chunk_offset > zlen)
	{
		return ERROR_INVALID_DATA;
	}
	return ERROR_SUCCESS;
}

typedef DWORD (*RESOURCE_DATA_CALLBACK)(const BYTE *data, size_t size, void *context);

static DWORD wim_for_each_resource_chunk(
	WIM_FILE *wim,
	const WIM_RESOURCE *resource,
	RESOURCE_DATA_CALLBACK callback,
	void *callback_context)
{
	uint64_t zlen = resource->zlen_flags & WIM_RESHDR_ZLEN_MASK;
	uint32_t chunk_size = wim->header.chunk_size != 0 ? wim->header.chunk_size : WIM_DEFAULT_CHUNK_SIZE;
	bool compressed = (resource->zlen_flags & (WIM_RESHDR_FLAG_COMPRESSED | WIM_RESHDR_FLAG_PACKED_STREAMS)) != 0;
	BYTE *in_buffer = NULL;
	BYTE *out_buffer = NULL;
	DWORD err = ERROR_SUCCESS;

	if (resource->offset > wim->file_size || zlen > wim->file_size - resource->offset)
	{
		return ERROR_INVALID_DATA;
	}
	if (!compressed)
	{
		uint64_t remaining = resource->length;
		uint64_t offset = 0;
		size_t buffer_size = chunk_size;
		in_buffer = (BYTE *)malloc(buffer_size);
		if (!in_buffer)
		{
			return ERROR_OUTOFMEMORY;
		}
		while (remaining != 0)
		{
			size_t to_read = remaining > buffer_size ? buffer_size : (size_t)remaining;
			err = read_exact_at(wim->handle, resource->offset + offset, in_buffer, to_read);
			if (err != ERROR_SUCCESS)
			{
				break;
			}
			err = callback(in_buffer, to_read, callback_context);
			if (err != ERROR_SUCCESS)
			{
				break;
			}
			offset += to_read;
			remaining -= to_read;
		}
		free(in_buffer);
		return err;
	}

	if ((wim->header.flags & WIM_HDR_FLAG_LZMS) != 0)
	{
		return ERROR_NOT_SUPPORTED;
	}
	out_buffer = (BYTE *)malloc(chunk_size);
	if (!out_buffer)
	{
		return ERROR_OUTOFMEMORY;
	}

	{
		uint64_t chunk_count = resource->length == 0 ? 0 : (resource->length + chunk_size - 1u) / chunk_size;
		for (uint64_t i = 0; i < chunk_count; ++i)
		{
			uint64_t offset = 0;
			uint64_t next_offset = 0;
			uint64_t compressed_size64;
			size_t compressed_size;
			size_t expected_size;

			err = wim_chunk_offset(wim, resource, (uint32_t)i, &offset);
			if (err != ERROR_SUCCESS)
			{
				break;
			}
			err = wim_chunk_offset(wim, resource, (uint32_t)(i + 1u), &next_offset);
			if (err != ERROR_SUCCESS)
			{
				break;
			}
			if (next_offset < offset)
			{
				err = ERROR_INVALID_DATA;
				break;
			}
			compressed_size64 = next_offset - offset;
			if (!checked_size_from_u64(compressed_size64, &compressed_size))
			{
				err = ERROR_INVALID_DATA;
				break;
			}
			expected_size = chunk_size;
			if (i == chunk_count - 1u)
			{
				uint64_t used_before = i * chunk_size;
				uint64_t remaining = resource->length - used_before;
				if (!checked_size_from_u64(remaining, &expected_size))
				{
					err = ERROR_INVALID_DATA;
					break;
				}
			}
			if (compressed_size == expected_size)
			{
				err = read_exact_at(wim->handle, resource->offset + offset, out_buffer, expected_size);
				if (err != ERROR_SUCCESS)
				{
					break;
				}
			}
			else
			{
				in_buffer = (BYTE *)realloc(in_buffer, compressed_size);
				if (!in_buffer)
				{
					err = ERROR_OUTOFMEMORY;
					break;
				}
				err = read_exact_at(wim->handle, resource->offset + offset, in_buffer, compressed_size);
				if (err != ERROR_SUCCESS)
				{
					break;
				}
				err = wim_decompress_chunk(wim, in_buffer, compressed_size, out_buffer, expected_size);
				if (err != ERROR_SUCCESS)
				{
					break;
				}
			}
			err = callback(out_buffer, expected_size, callback_context);
			if (err != ERROR_SUCCESS)
			{
				break;
			}
		}
	}

	free(in_buffer);
	free(out_buffer);
	return err;
}

typedef struct ALLOC_READ_CONTEXT
{
	BYTE *buffer;
	size_t capacity;
	size_t offset;
} ALLOC_READ_CONTEXT;

static DWORD alloc_read_callback(const BYTE *data, size_t size, void *context)
{
	ALLOC_READ_CONTEXT *ctx = (ALLOC_READ_CONTEXT *)context;
	if (size > ctx->capacity - ctx->offset)
	{
		return ERROR_INVALID_DATA;
	}
	memcpy(ctx->buffer + ctx->offset, data, size);
	ctx->offset += size;
	return ERROR_SUCCESS;
}

static DWORD wim_read_resource_alloc(WIM_FILE *wim, const WIM_RESOURCE *resource, BYTE **data, size_t *data_size)
{
	ALLOC_READ_CONTEXT ctx;
	size_t size;
	DWORD err;

	if (!checked_size_from_u64(resource->length, &size))
	{
		return ERROR_INVALID_DATA;
	}
	ctx.buffer = (BYTE *)malloc(size == 0 ? 1u : size);
	if (!ctx.buffer)
	{
		return ERROR_OUTOFMEMORY;
	}
	ctx.capacity = size;
	ctx.offset = 0;
	err = wim_for_each_resource_chunk(wim, resource, alloc_read_callback, &ctx);
	if (err != ERROR_SUCCESS)
	{
		free(ctx.buffer);
		return err;
	}
	if (ctx.offset != size)
	{
		free(ctx.buffer);
		return ERROR_INVALID_DATA;
	}
	*data = ctx.buffer;
	*data_size = size;
	return ERROR_SUCCESS;
}

static int lookup_compare_hash(const void *a, const void *b)
{
	const WIM_LOOKUP_ITEM *left = (const WIM_LOOKUP_ITEM *)a;
	const WIM_LOOKUP_ITEM *right = (const WIM_LOOKUP_ITEM *)b;
	return memcmp(left->hash, right->hash, WIM_PROVIDER_HASH_SIZE);
}

static const WIM_LOOKUP_ITEM *wim_lookup_hash(const WIM_FILE *wim, const BYTE hash[WIM_PROVIDER_HASH_SIZE])
{
	WIM_LOOKUP_ITEM key;
	if (hash_is_zero(hash))
	{
		return NULL;
	}
	ZeroMemory(&key, sizeof(key));
	memcpy(key.hash, hash, WIM_PROVIDER_HASH_SIZE);
	return (const WIM_LOOKUP_ITEM *)bsearch(&key, wim->lookup, wim->lookup_count, sizeof(wim->lookup[0]), lookup_compare_hash);
}

static DWORD wim_open(const wchar_t *wim_path, WIM_FILE *wim)
{
	wchar_t *io_path;
	LARGE_INTEGER file_size;
	DWORD err;

	ZeroMemory(wim, sizeof(*wim));
	io_path = normalize_path_for_io(wim_path);
	if (!io_path)
	{
		return last_error_or(ERROR_INVALID_PARAMETER);
	}
	wim->handle = CreateFileW(
		io_path,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);
	free(io_path);
	if (wim->handle == INVALID_HANDLE_VALUE)
	{
		return last_error_or(ERROR_FILE_NOT_FOUND);
	}
	if (!GetFileSizeEx(wim->handle, &file_size) || file_size.QuadPart < (LONGLONG)sizeof(WIM_HEADER_DISK))
	{
		err = last_error_or(ERROR_INVALID_DATA);
		CloseHandle(wim->handle);
		wim->handle = INVALID_HANDLE_VALUE;
		return err == ERROR_SUCCESS ? ERROR_INVALID_DATA : err;
	}
	wim->file_size = (uint64_t)file_size.QuadPart;
	err = read_exact_at(wim->handle, 0, &wim->header, sizeof(wim->header));
	if (err != ERROR_SUCCESS)
	{
		CloseHandle(wim->handle);
		wim->handle = INVALID_HANDLE_VALUE;
		return err;
	}
	if (memcmp(wim->header.signature, WIM_SIGNATURE, sizeof(wim->header.signature)) != 0 ||
		wim->header.header_size < sizeof(WIM_HEADER_DISK) ||
		wim->header.part_number != 1 ||
		wim->header.total_parts != 1)
	{
		CloseHandle(wim->handle);
		wim->handle = INVALID_HANDLE_VALUE;
		return ERROR_INVALID_DATA;
	}
	if ((wim->header.flags & WIM_HDR_FLAG_LZMS) != 0)
	{
		CloseHandle(wim->handle);
		wim->handle = INVALID_HANDLE_VALUE;
		return ERROR_NOT_SUPPORTED;
	}
	return ERROR_SUCCESS;
}

static void wim_close(WIM_FILE *wim)
{
	if (wim->handle && wim->handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(wim->handle);
	}
	free(wim->lookup);
	free(wim->metadata_resources);
	free(wim->metadata_hashes);
	ZeroMemory(wim, sizeof(*wim));
}

static WIM_RESOURCE resource_from_disk(WIM_RESOURCE_HEADER_DISK disk)
{
	WIM_RESOURCE resource;
	resource.zlen_flags = disk.zlen_flags;
	resource.offset = disk.offset;
	resource.length = disk.length;
	return resource;
}

static DWORD wim_load_lookup_table(WIM_FILE *wim)
{
	WIM_RESOURCE lookup_resource = resource_from_disk(wim->header.lookup);
	BYTE *data = NULL;
	size_t data_size = 0;
	size_t count;
	DWORD err;

	err = wim_read_resource_alloc(wim, &lookup_resource, &data, &data_size);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}
	if (data_size % sizeof(WIM_LOOKUP_ENTRY_DISK) != 0)
	{
		free(data);
		return ERROR_INVALID_DATA;
	}
	count = data_size / sizeof(WIM_LOOKUP_ENTRY_DISK);
	wim->lookup = (WIM_LOOKUP_ITEM *)xcalloc(count == 0 ? 1u : count, sizeof(wim->lookup[0]));
	if (!wim->lookup)
	{
		free(data);
		return ERROR_OUTOFMEMORY;
	}
	wim->lookup_count = count;

	for (size_t i = 0; i < count; ++i)
	{
		WIM_LOOKUP_ENTRY_DISK *entry = (WIM_LOOKUP_ENTRY_DISK *)(data + (i * sizeof(WIM_LOOKUP_ENTRY_DISK)));
		bool is_metadata = (entry->resource.zlen_flags & WIM_RESHDR_FLAG_METADATA) != 0;
		wim->lookup[i].resource = resource_from_disk(entry->resource);
		wim->lookup[i].part_number = entry->part_number;
		wim->lookup[i].ref_count = entry->ref_count;
		wim->lookup[i].is_metadata = is_metadata;
		memcpy(wim->lookup[i].hash, entry->hash, WIM_PROVIDER_HASH_SIZE);
		if (is_metadata)
		{
			WIM_RESOURCE *new_resources;
			BYTE(*new_hashes)
			[WIM_PROVIDER_HASH_SIZE];
			size_t new_count = wim->metadata_count + 1u;

			new_resources = (WIM_RESOURCE *)realloc(wim->metadata_resources, new_count * sizeof(wim->metadata_resources[0]));
			if (!new_resources)
			{
				free(data);
				return ERROR_OUTOFMEMORY;
			}
			wim->metadata_resources = new_resources;
			new_hashes = (BYTE(*)[WIM_PROVIDER_HASH_SIZE])realloc(wim->metadata_hashes, new_count * sizeof(wim->metadata_hashes[0]));
			if (!new_hashes)
			{
				free(data);
				return ERROR_OUTOFMEMORY;
			}
			wim->metadata_hashes = new_hashes;
			wim->metadata_resources[wim->metadata_count] = wim->lookup[i].resource;
			memcpy(wim->metadata_hashes[wim->metadata_count], entry->hash, WIM_PROVIDER_HASH_SIZE);
			wim->metadata_count = new_count;
		}
	}
	qsort(wim->lookup, wim->lookup_count, sizeof(wim->lookup[0]), lookup_compare_hash);
	free(data);
	if (wim->metadata_count != wim->header.image_count)
	{
		return ERROR_INVALID_DATA;
	}
	return ERROR_SUCCESS;
}

static DWORD read_security_table(const BYTE *metadata, size_t metadata_size, WIM_SECURITY_TABLE *table)
{
	const WIM_SECURITY_HEADER_DISK *header;
	uint64_t total_length;
	uint64_t sizes_bytes;
	uint64_t base_size;
	const BYTE *p;

	ZeroMemory(table, sizeof(*table));
	if (metadata_size < sizeof(WIM_SECURITY_HEADER_DISK))
	{
		return ERROR_INVALID_DATA;
	}
	header = (const WIM_SECURITY_HEADER_DISK *)metadata;
	total_length = align8_u64(header->total_length);
	if (total_length == 0)
	{
		total_length = 8;
	}
	if (total_length > metadata_size || header->num_entries > 0x80000000u)
	{
		return ERROR_INVALID_DATA;
	}
	sizes_bytes = (uint64_t)header->num_entries * sizeof(uint64_t);
	base_size = sizeof(WIM_SECURITY_HEADER_DISK) + sizes_bytes;
	if (base_size > total_length)
	{
		return ERROR_INVALID_DATA;
	}

	table->total_length = (uint32_t)total_length;
	table->num_entries = header->num_entries;
	if (table->num_entries == 0)
	{
		return ERROR_SUCCESS;
	}
	table->sizes = (uint64_t *)xcalloc(table->num_entries, sizeof(table->sizes[0]));
	table->descriptors = (BYTE **)xcalloc(table->num_entries, sizeof(table->descriptors[0]));
	if (!table->sizes || !table->descriptors)
	{
		return ERROR_OUTOFMEMORY;
	}

	p = metadata + base_size;
	for (uint32_t i = 0; i < table->num_entries; ++i)
	{
		uint64_t desc_size;
		memcpy(&desc_size, metadata + sizeof(WIM_SECURITY_HEADER_DISK) + ((size_t)i * sizeof(uint64_t)), sizeof(desc_size));
		if (desc_size > UINT32_MAX || (uint64_t)(p - metadata) + desc_size > total_length)
		{
			return ERROR_INVALID_DATA;
		}
		table->sizes[i] = desc_size;
		if (desc_size != 0)
		{
			size_t size = (size_t)desc_size;
			table->descriptors[i] = (BYTE *)malloc(size);
			if (!table->descriptors[i])
			{
				return ERROR_OUTOFMEMORY;
			}
			memcpy(table->descriptors[i], p, size);
		}
		p += desc_size;
	}
	return ERROR_SUCCESS;
}

static void free_security_table(WIM_SECURITY_TABLE *table)
{
	if (table->descriptors)
	{
		for (uint32_t i = 0; i < table->num_entries; ++i)
		{
			free(table->descriptors[i]);
		}
	}
	free(table->descriptors);
	free(table->sizes);
	ZeroMemory(table, sizeof(*table));
}

static wchar_t *utf16_name_dup(const BYTE *source, uint16_t byte_len)
{
	size_t char_count;
	wchar_t *name;

	if ((byte_len & 1u) != 0)
	{
		SetLastError(ERROR_INVALID_DATA);
		return NULL;
	}
	char_count = byte_len / sizeof(wchar_t);
	name = (wchar_t *)calloc(char_count + 1u, sizeof(wchar_t));
	if (!name)
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}
	memcpy(name, source, byte_len);
	name[char_count] = L'\0';
	return name;
}

static void free_dentry(WIM_DENTRY *entry)
{
	if (!entry)
	{
		return;
	}
	free(entry->name);
	if (entry->streams)
	{
		for (size_t i = 0; i < entry->num_streams; ++i)
		{
			free(entry->streams[i].name);
		}
		free(entry->streams);
	}
	ZeroMemory(entry, sizeof(*entry));
}

static DWORD parse_streams(APPLY_CONTEXT *ctx, const WIM_DENTRY_DISK *disk, size_t dentry_offset, WIM_DENTRY *entry, size_t *next_offset)
{
	uint64_t aligned_length64 = align8_u64(disk->length);
	size_t aligned_length;
	size_t stream_offset;
	DWORD err = ERROR_SUCCESS;

	if (!checked_size_from_u64(aligned_length64, &aligned_length))
	{
		return ERROR_INVALID_DATA;
	}
	entry->num_streams = 1u + disk->num_extra_streams;
	entry->streams = (WIM_STREAM *)xcalloc(entry->num_streams, sizeof(entry->streams[0]));
	if (!entry->streams)
	{
		return ERROR_OUTOFMEMORY;
	}
	memcpy(entry->streams[0].hash, disk->main_hash, WIM_PROVIDER_HASH_SIZE);

	stream_offset = dentry_offset + aligned_length;
	for (uint16_t i = 0; i < disk->num_extra_streams; ++i)
	{
		const WIM_STREAM_ENTRY_DISK *stream_disk;
		uint64_t stream_len64;
		size_t stream_len;
		const BYTE *name_source;
		WIM_STREAM *stream = &entry->streams[(size_t)i + 1u];

		if (stream_offset > ctx->metadata_size ||
			ctx->metadata_size - stream_offset < sizeof(WIM_STREAM_ENTRY_DISK))
		{
			return ERROR_INVALID_DATA;
		}
		stream_disk = (const WIM_STREAM_ENTRY_DISK *)(ctx->metadata + stream_offset);
		stream_len64 = align8_u64(stream_disk->length);
		if (!checked_size_from_u64(stream_len64, &stream_len) ||
			stream_len < sizeof(WIM_STREAM_ENTRY_DISK) ||
			stream_offset > ctx->metadata_size - stream_len)
		{
			return ERROR_INVALID_DATA;
		}
		if ((stream_disk->name_nbytes & 1u) != 0 ||
			(size_t)stream_disk->name_nbytes + sizeof(WIM_STREAM_ENTRY_DISK) > stream_len)
		{
			return ERROR_INVALID_DATA;
		}
		memcpy(stream->hash, stream_disk->hash, WIM_PROVIDER_HASH_SIZE);
		if (stream_disk->name_nbytes != 0)
		{
			name_source = ctx->metadata + stream_offset + sizeof(WIM_STREAM_ENTRY_DISK);
			stream->name = utf16_name_dup(name_source, stream_disk->name_nbytes);
			if (!stream->name)
			{
				return last_error_or(ERROR_INVALID_DATA);
			}
		}
		stream_offset += stream_len;
	}
	*next_offset = stream_offset;
	(void)err;
	return ERROR_SUCCESS;
}

static DWORD parse_dentry_at(APPLY_CONTEXT *ctx, size_t offset, WIM_DENTRY *entry, size_t *next_offset, bool *is_terminator)
{
	const WIM_DENTRY_DISK *disk;
	uint64_t entry_len64;
	size_t entry_len;
	size_t name_offset;
	size_t short_offset;
	DWORD err;

	ZeroMemory(entry, sizeof(*entry));
	*is_terminator = false;
	if (offset > ctx->metadata_size || ctx->metadata_size - offset < sizeof(uint64_t))
	{
		return ERROR_INVALID_DATA;
	}
	memcpy(&entry_len64, ctx->metadata + offset, sizeof(entry_len64));
	if (entry_len64 == 0)
	{
		*is_terminator = true;
		*next_offset = offset + sizeof(uint64_t);
		return ERROR_SUCCESS;
	}
	if (!checked_size_from_u64(entry_len64, &entry_len) ||
		entry_len < sizeof(WIM_DENTRY_DISK) ||
		offset > ctx->metadata_size - entry_len)
	{
		return ERROR_INVALID_DATA;
	}
	disk = (const WIM_DENTRY_DISK *)(ctx->metadata + offset);
	if ((disk->name_nbytes & 1u) != 0 || (disk->short_name_nbytes & 1u) != 0)
	{
		return ERROR_INVALID_DATA;
	}
	name_offset = offset + sizeof(WIM_DENTRY_DISK);
	if ((size_t)disk->name_nbytes + sizeof(wchar_t) > entry_len - sizeof(WIM_DENTRY_DISK))
	{
		return ERROR_INVALID_DATA;
	}
	short_offset = name_offset + (size_t)disk->name_nbytes + sizeof(wchar_t);
	if (short_offset < name_offset || short_offset > offset + entry_len)
	{
		return ERROR_INVALID_DATA;
	}
	if (disk->short_name_nbytes != 0 &&
		(size_t)disk->short_name_nbytes + sizeof(wchar_t) > (offset + entry_len) - short_offset)
	{
		return ERROR_INVALID_DATA;
	}

	entry->attributes = disk->attributes;
	entry->security_id = disk->security_id;
	entry->subdir_offset = disk->subdir_offset;
	entry->creation_time = disk->creation_time;
	entry->last_access_time = disk->last_access_time;
	entry->last_write_time = disk->last_write_time;
	entry->reparse_tag = disk->link.reparse.reparse_tag;
	entry->rp_reserved = disk->link.reparse.rp_reserved;
	entry->rp_flags = disk->link.reparse.rp_flags;
	entry->hard_link_group_id = disk->link.hard_link_group_id;
	entry->name = utf16_name_dup(ctx->metadata + name_offset, disk->name_nbytes);
	if (!entry->name)
	{
		return last_error_or(ERROR_INVALID_DATA);
	}

	err = parse_streams(ctx, disk, offset, entry, next_offset);
	if (err != ERROR_SUCCESS)
	{
		free_dentry(entry);
		return err;
	}
	return ERROR_SUCCESS;
}

static void assign_stream_kinds(WIM_DENTRY *entry)
{
	bool found_reparse = false;
	bool found_data = false;
	bool is_reparse = (entry->attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
	bool encrypted = (entry->attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0;

	if (encrypted)
	{
		for (size_t i = 0; i < entry->num_streams; ++i)
		{
			if (!entry->streams[i].name && !hash_is_zero(entry->streams[i].hash))
			{
				entry->streams[i].kind = STREAM_KIND_EFS_RAW;
				return;
			}
		}
	}

	for (size_t i = 0; i < entry->num_streams; ++i)
	{
		WIM_STREAM *stream = &entry->streams[i];
		if (stream->name)
		{
			stream->kind = STREAM_KIND_DATA;
		}
		else if (i != 0 || !hash_is_zero(stream->hash))
		{
			if (is_reparse && !found_reparse)
			{
				found_reparse = true;
				stream->kind = STREAM_KIND_REPARSE;
			}
			else if (!found_data)
			{
				found_data = true;
				stream->kind = STREAM_KIND_DATA;
			}
		}
	}

	if (!found_reparse && !found_data && entry->num_streams != 0)
	{
		entry->streams[0].kind = is_reparse ? STREAM_KIND_REPARSE : STREAM_KIND_DATA;
	}
}

static DWORD resolve_stream_resources(APPLY_CONTEXT *ctx, WIM_DENTRY *entry)
{
	for (size_t i = 0; i < entry->num_streams; ++i)
	{
		WIM_STREAM *stream = &entry->streams[i];
		const WIM_LOOKUP_ITEM *item;

		if (hash_is_zero(stream->hash))
		{
			stream->size = 0;
			stream->has_resource = false;
			continue;
		}
		item = wim_lookup_hash(ctx->wim, stream->hash);
		if (!item)
		{
			return ERROR_INVALID_DATA;
		}
		stream->size = item->resource.length;
		stream->has_resource = true;
	}
	return ERROR_SUCCESS;
}

static WIM_STREAM *find_stream(WIM_DENTRY *entry, STREAM_KIND kind, bool named)
{
	for (size_t i = 0; i < entry->num_streams; ++i)
	{
		if (entry->streams[i].kind == kind && ((entry->streams[i].name != NULL) == named))
		{
			return &entry->streams[i];
		}
	}
	return NULL;
}

static DWORD hard_link_lookup(HARD_LINK_TABLE *table, uint64_t id, const wchar_t **first_path)
{
	for (size_t i = 0; i < table->count; ++i)
	{
		if (table->entries[i].id == id)
		{
			*first_path = table->entries[i].first_path;
			return ERROR_SUCCESS;
		}
	}
	*first_path = NULL;
	return ERROR_NOT_FOUND;
}

static DWORD hard_link_add(HARD_LINK_TABLE *table, uint64_t id, const wchar_t *first_path)
{
	HARD_LINK_ENTRY *new_entries;

	if (id == 0)
	{
		return ERROR_SUCCESS;
	}
	if (table->count == table->capacity)
	{
		size_t new_capacity = table->capacity == 0 ? 64u : table->capacity * 2u;
		if (new_capacity < table->capacity)
		{
			return ERROR_OUTOFMEMORY;
		}
		new_entries = (HARD_LINK_ENTRY *)realloc(table->entries, new_capacity * sizeof(table->entries[0]));
		if (!new_entries)
		{
			return ERROR_OUTOFMEMORY;
		}
		table->entries = new_entries;
		table->capacity = new_capacity;
	}
	table->entries[table->count].id = id;
	table->entries[table->count].first_path = xwcsdup(first_path);
	if (!table->entries[table->count].first_path)
	{
		return ERROR_OUTOFMEMORY;
	}
	table->count++;
	return ERROR_SUCCESS;
}

static void free_hard_link_table(HARD_LINK_TABLE *table)
{
	for (size_t i = 0; i < table->count; ++i)
	{
		free(table->entries[i].first_path);
	}
	free(table->entries);
	ZeroMemory(table, sizeof(*table));
}

static DWORD apply_security(APPLY_CONTEXT *ctx, const wchar_t *path, uint32_t security_id)
{
	SECURITY_INFORMATION all_info = OWNER_SECURITY_INFORMATION |
									GROUP_SECURITY_INFORMATION |
									DACL_SECURITY_INFORMATION |
									SACL_SECURITY_INFORMATION;
	SECURITY_INFORMATION no_sacl = OWNER_SECURITY_INFORMATION |
								   GROUP_SECURITY_INFORMATION |
								   DACL_SECURITY_INFORMATION;
	BYTE *descriptor;
	DWORD err;

	if ((ctx->flags & WOFMNT_MOUNT_FLAG_DISABLE_ACLS) != 0 ||
		security_id == WIM_NO_SECURITY_ID ||
		security_id >= ctx->security.num_entries ||
		ctx->security.sizes[security_id] == 0)
	{
		return ERROR_SUCCESS;
	}

	descriptor = ctx->security.descriptors[security_id];
	if (SetFileSecurityW(path, all_info, (PSECURITY_DESCRIPTOR)descriptor))
	{
		if (ctx->stats)
		{
			ctx->stats->security_descriptors_applied++;
		}
		return ERROR_SUCCESS;
	}
	err = last_error_or(ERROR_ACCESS_DENIED);
	if (SetFileSecurityW(path, no_sacl, (PSECURITY_DESCRIPTOR)descriptor))
	{
		if (ctx->stats)
		{
			ctx->stats->security_descriptors_applied++;
			ctx->stats->security_descriptor_failures++;
		}
		progress_event(ctx, WOFMNT_PROGRESS_WARNING, path, L"SACL was not applied");
		return ERROR_SUCCESS;
	}
	if (SetFileSecurityW(path, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)descriptor))
	{
		if (ctx->stats)
		{
			ctx->stats->security_descriptors_applied++;
			ctx->stats->security_descriptor_failures++;
		}
		progress_event(ctx, WOFMNT_PROGRESS_WARNING, path, L"owner/group/SACL were not applied");
		return ERROR_SUCCESS;
	}
	if (ctx->stats)
	{
		ctx->stats->security_descriptor_failures++;
	}
	progress_event(ctx, WOFMNT_PROGRESS_WARNING, path, L"security descriptor was not applied");
	if ((ctx->flags & WOFMNT_MOUNT_FLAG_STRICT_ACLS) != 0)
	{
		return err;
	}
	return ERROR_SUCCESS;
}

static DWORD apply_times_and_attributes(const wchar_t *path, const WIM_DENTRY *entry)
{
	DWORD attributes;
	HANDLE h;
	FILETIME created;
	FILETIME accessed;
	FILETIME written;

	h = CreateFileW(
		path,
		FILE_WRITE_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		((entry->attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? FILE_FLAG_BACKUP_SEMANTICS : 0),
		NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		created.dwLowDateTime = (DWORD)entry->creation_time;
		created.dwHighDateTime = (DWORD)(entry->creation_time >> 32);
		accessed.dwLowDateTime = (DWORD)entry->last_access_time;
		accessed.dwHighDateTime = (DWORD)(entry->last_access_time >> 32);
		written.dwLowDateTime = (DWORD)entry->last_write_time;
		written.dwHighDateTime = (DWORD)(entry->last_write_time >> 32);
		(void)SetFileTime(
			h,
			entry->creation_time != 0 ? &created : NULL,
			entry->last_access_time != 0 ? &accessed : NULL,
			entry->last_write_time != 0 ? &written : NULL);
		CloseHandle(h);
	}

	attributes = entry->attributes;
	attributes &= ~(FILE_ATTRIBUTE_DIRECTORY |
					FILE_ATTRIBUTE_REPARSE_POINT |
					FILE_ATTRIBUTE_SPARSE_FILE |
					FILE_ATTRIBUTE_COMPRESSED |
					FILE_ATTRIBUTE_ENCRYPTED);
	if (attributes == 0)
	{
		attributes = FILE_ATTRIBUTE_NORMAL;
	}
	if (!SetFileAttributesW(path, attributes))
	{
		return last_error_or(ERROR_ACCESS_DENIED);
	}
	return ERROR_SUCCESS;
}

typedef struct RESOURCE_WRITE_CONTEXT
{
	HANDLE handle;
} RESOURCE_WRITE_CONTEXT;

static DWORD resource_write_callback(const BYTE *data, size_t size, void *context)
{
	RESOURCE_WRITE_CONTEXT *write_ctx = (RESOURCE_WRITE_CONTEXT *)context;
	return write_exact(write_ctx->handle, data, size);
}

static DWORD wim_extract_resource_to_handle(WIM_FILE *wim, const WIM_RESOURCE *resource, HANDLE out_handle)
{
	RESOURCE_WRITE_CONTEXT write_ctx;
	write_ctx.handle = out_handle;
	return wim_for_each_resource_chunk(wim, resource, resource_write_callback, &write_ctx);
}

static DWORD wim_extract_hash_to_handle(APPLY_CONTEXT *ctx, const BYTE hash[WIM_PROVIDER_HASH_SIZE], HANDLE out_handle)
{
	const WIM_LOOKUP_ITEM *item;

	if (hash_is_zero(hash))
	{
		return ERROR_SUCCESS;
	}
	item = wim_lookup_hash(ctx->wim, hash);
	if (!item)
	{
		return ERROR_INVALID_DATA;
	}
	return wim_extract_resource_to_handle(ctx->wim, &item->resource, out_handle);
}

static DWORD wim_extract_hash_alloc(
	APPLY_CONTEXT *ctx,
	const BYTE hash[WIM_PROVIDER_HASH_SIZE],
	size_t max_size,
	BYTE **data,
	size_t *data_size)
{
	const WIM_LOOKUP_ITEM *item;

	*data = NULL;
	*data_size = 0;
	if (hash_is_zero(hash))
	{
		*data = (BYTE *)calloc(1u, 1u);
		if (!*data)
		{
			return ERROR_OUTOFMEMORY;
		}
		return ERROR_SUCCESS;
	}
	item = wim_lookup_hash(ctx->wim, hash);
	if (!item)
	{
		return ERROR_INVALID_DATA;
	}
	if (item->resource.length > max_size)
	{
		return ERROR_INVALID_DATA;
	}
	return wim_read_resource_alloc(ctx->wim, &item->resource, data, data_size);
}

DWORD WofMntSetWimExternalBacking(
	HANDLE file_handle,
	LARGE_INTEGER data_source_id,
	const BYTE resource_hash[20])
{
	struct
	{
		WOF_EXTERNAL_INFO wof_info;
		WIM_PROVIDER_EXTERNAL_INFO wim_info;
	} input;
	DWORD bytes_returned = 0;
	DWORD err = ERROR_INVALID_FUNCTION;

	ZeroMemory(&input, sizeof(input));
	input.wof_info.Version = WOF_CURRENT_VERSION;
	input.wof_info.Provider = WOF_PROVIDER_WIM;
	input.wim_info.Version = WIM_PROVIDER_CURRENT_VERSION;
	input.wim_info.Flags = 0;
	input.wim_info.DataSourceId = data_source_id;
	memcpy(input.wim_info.ResourceHash, resource_hash, WIM_PROVIDER_HASH_SIZE);

	for (uint32_t retry = 0; retry < 4u; ++retry)
	{
		if (DeviceIoControl(
				file_handle,
				FSCTL_SET_EXTERNAL_BACKING,
				&input,
				sizeof(input),
				NULL,
				0,
				&bytes_returned,
				NULL))
		{
			err = ERROR_SUCCESS;
			goto out;
		}
		if (retry != 3u)
		{
			Sleep(100);
		}
	}
	err = last_error_or(ERROR_INVALID_FUNCTION);

out:
	return err;
}

DWORD WofMntRegisterWimDataSource(
	const wchar_t *target_directory,
	const wchar_t *wim_path,
	uint32_t image_index,
	uint32_t wim_type,
	LARGE_INTEGER *data_source_id)
{
	wchar_t drive_path[7];
	wchar_t *full_wim = NULL;
	wchar_t *nt_wim_path = NULL;
	BYTE *input = NULL;
	size_t nt_wim_chars;
	size_t nt_wim_bytes;
	size_t input_size;
	WOF_EXTERNAL_INFO *wof_info;
	WIM_PROVIDER_ADD_OVERLAY_INPUT *add_input;
	HANDLE volume = INVALID_HANDLE_VALUE;
	DWORD bytes_returned = 0;
	DWORD err = ERROR_SUCCESS;

	if (!target_directory || !wim_path || !data_source_id || image_index == 0)
	{
		err = ERROR_INVALID_PARAMETER;
		goto fail;
	}

	err = get_drive_device_path(target_directory, drive_path);
	if (err != ERROR_SUCCESS)
	{
		goto fail;
	}
	full_wim = make_full_path_no_prefix(wim_path);
	if (!full_wim)
	{
		err = last_error_or(ERROR_INVALID_PARAMETER);
		goto fail;
	}
	if (wcslen(full_wim) < 3u || full_wim[1] != L':')
	{
		err = ERROR_NOT_SUPPORTED;
		goto fail;
	}

	nt_wim_chars = wcslen(full_wim) + 4u;
	if (nt_wim_chars > (SIZE_MAX / sizeof(wchar_t)) - 1u)
	{
		err = ERROR_OUTOFMEMORY;
		goto fail;
	}
	nt_wim_path = (wchar_t *)calloc(nt_wim_chars + 1u, sizeof(wchar_t));
	if (!nt_wim_path)
	{
		err = ERROR_OUTOFMEMORY;
		goto fail;
	}
	memcpy(nt_wim_path, L"\\??\\", 4u * sizeof(wchar_t));
	memcpy(nt_wim_path + 4u, full_wim, (wcslen(full_wim) + 1u) * sizeof(wchar_t));

	nt_wim_bytes = nt_wim_chars * sizeof(wchar_t);
	input_size = sizeof(WOF_EXTERNAL_INFO) + sizeof(WIM_PROVIDER_ADD_OVERLAY_INPUT) + nt_wim_bytes;
	input = (BYTE *)calloc(1u, input_size);
	if (!input)
	{
		err = ERROR_OUTOFMEMORY;
		goto fail;
	}
	wof_info = (WOF_EXTERNAL_INFO *)input;
	wof_info->Version = WOF_CURRENT_VERSION;
	wof_info->Provider = WOF_PROVIDER_WIM;
	add_input = (WIM_PROVIDER_ADD_OVERLAY_INPUT *)(wof_info + 1);
	add_input->WimType = wim_type;
	add_input->WimIndex = image_index;
	add_input->WimFileNameOffset = sizeof(*add_input);
	add_input->WimFileNameLength = (DWORD)nt_wim_bytes;
	memcpy(add_input + 1, nt_wim_path, nt_wim_bytes);

	volume = CreateFileW(
		drive_path,
		GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (volume == INVALID_HANDLE_VALUE)
	{
		err = last_error_or(ERROR_OPEN_FAILED);
		goto fail;
	}

	if (!DeviceIoControl(
			volume,
			FSCTL_ADD_OVERLAY,
			input,
			(DWORD)input_size,
			data_source_id,
			sizeof(*data_source_id),
			&bytes_returned,
			NULL))
	{
		err = last_error_or(ERROR_INVALID_FUNCTION);
		if (err == ERROR_INVALID_FUNCTION || err == ERROR_INVALID_PARAMETER)
		{
			DWORD attach_err = try_attach_wof(drive_path + 4);
			if (attach_err == ERROR_SUCCESS &&
				DeviceIoControl(
					volume,
					FSCTL_ADD_OVERLAY,
					input,
					(DWORD)input_size,
					data_source_id,
					sizeof(*data_source_id),
					&bytes_returned,
					NULL))
			{
				err = ERROR_SUCCESS;
			}
		}
	}
	else
	{
		err = ERROR_SUCCESS;
	}

	if (err != ERROR_SUCCESS)
	{
		goto fail;
	}
	if (bytes_returned != sizeof(*data_source_id))
	{
		err = ERROR_INVALID_DATA;
		goto fail;
	}

fail:
	if (volume != INVALID_HANDLE_VALUE)
	{
		CloseHandle(volume);
	}
	free(input);
	free(nt_wim_path);
	free(full_wim);
	return err;
}

DWORD WofMntRemoveWimDataSource(
	const wchar_t *target_directory,
	LARGE_INTEGER data_source_id)
{
	wchar_t drive_path[7];
	struct
	{
		WOF_EXTERNAL_INFO wof_info;
		WIM_PROVIDER_REMOVE_OVERLAY_INPUT remove_input;
	} input;
	HANDLE volume = INVALID_HANDLE_VALUE;
	DWORD bytes_returned = 0;
	DWORD err = ERROR_SUCCESS;

	err = get_drive_device_path(target_directory, drive_path);
	if (err != ERROR_SUCCESS)
	{
		goto fail;
	}
	ZeroMemory(&input, sizeof(input));
	input.wof_info.Version = WOF_CURRENT_VERSION;
	input.wof_info.Provider = WOF_PROVIDER_WIM;
	input.remove_input.DataSourceId = data_source_id;

	volume = CreateFileW(
		drive_path,
		GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (volume == INVALID_HANDLE_VALUE)
	{
		err = last_error_or(ERROR_OPEN_FAILED);
		goto fail;
	}
	if (!DeviceIoControl(volume, FSCTL_REMOVE_OVERLAY, &input, sizeof(input), NULL, 0, &bytes_returned, NULL))
	{
		err = last_error_or(ERROR_INVALID_FUNCTION);
	}
	else
	{
		err = ERROR_SUCCESS;
	}

fail:
	if (volume != INVALID_HANDLE_VALUE)
	{
		CloseHandle(volume);
	}
	return err;
}

static DWORD create_manifest(const wchar_t *target_path, const wchar_t *wim_path, uint32_t image_index, LARGE_INTEGER data_source_id)
{
	wchar_t *manifest_path = make_child_path(target_path, MANIFEST_NAME);
	wchar_t *full_wim = NULL;
	HANDLE file;
	WOFMNT_MANIFEST_HEADER header;
	DWORD err;

	if (!manifest_path)
	{
		return last_error_or(ERROR_INVALID_NAME);
	}
	full_wim = make_full_path_no_prefix(wim_path);
	if (!full_wim)
	{
		free(manifest_path);
		return last_error_or(ERROR_INVALID_PARAMETER);
	}
	file = CreateFileW(
		manifest_path,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
		NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		err = last_error_or(ERROR_CREATE_FAILED);
		free(full_wim);
		free(manifest_path);
		return err;
	}
	ZeroMemory(&header, sizeof(header));
	memcpy(header.magic, MANIFEST_MAGIC, sizeof(MANIFEST_MAGIC));
	header.version = MANIFEST_VERSION;
	header.image_index = image_index;
	header.data_source_id = data_source_id.QuadPart;
	header.wim_path_chars = (uint32_t)(wcslen(full_wim) + 1u);

	err = write_exact(file, &header, sizeof(header));
	if (err == ERROR_SUCCESS)
	{
		err = write_exact(file, full_wim, (size_t)header.wim_path_chars * sizeof(wchar_t));
	}
	CloseHandle(file);
	free(full_wim);
	free(manifest_path);
	return err;
}

static DWORD read_manifest(const wchar_t *target_path, LARGE_INTEGER *data_source_id)
{
	wchar_t *manifest_path = make_child_path(target_path, MANIFEST_NAME);
	HANDLE file;
	WOFMNT_MANIFEST_HEADER header;
	DWORD err;

	if (!manifest_path)
	{
		return last_error_or(ERROR_INVALID_NAME);
	}
	file = CreateFileW(
		manifest_path,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	free(manifest_path);
	if (file == INVALID_HANDLE_VALUE)
	{
		return last_error_or(ERROR_FILE_NOT_FOUND);
	}
	err = read_exact_at(file, 0, &header, sizeof(header));
	CloseHandle(file);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}
	if (memcmp(header.magic, MANIFEST_MAGIC, sizeof(MANIFEST_MAGIC)) != 0 ||
		header.version != MANIFEST_VERSION)
	{
		return ERROR_INVALID_DATA;
	}
	data_source_id->QuadPart = header.data_source_id;
	return ERROR_SUCCESS;
}

static HANDLE create_file_for_write(const wchar_t *path, DWORD creation_disposition, DWORD flags)
{
	return CreateFileW(
		path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		creation_disposition,
		FILE_ATTRIBUTE_NORMAL | flags,
		NULL);
}

static DWORD materialize_hash_to_file(APPLY_CONTEXT *ctx, const BYTE hash[WIM_PROVIDER_HASH_SIZE], const wchar_t *path, DWORD creation_disposition)
{
	HANDLE file = create_file_for_write(path, creation_disposition, 0);
	DWORD err;

	if (file == INVALID_HANDLE_VALUE)
	{
		return last_error_or(ERROR_CREATE_FAILED);
	}
	err = wim_extract_hash_to_handle(ctx, hash, file);
	CloseHandle(file);
	if (err == ERROR_SUCCESS && ctx->stats)
	{
		ctx->stats->files_materialized++;
	}
	return err;
}

static DWORD materialize_named_stream(APPLY_CONTEXT *ctx, const wchar_t *path, const WIM_STREAM *stream, bool parent_is_directory)
{
	wchar_t *stream_path;
	HANDLE file;
	DWORD err;

	if (!stream->name)
	{
		return ERROR_SUCCESS;
	}
	stream_path = make_stream_path(path, stream->name);
	if (!stream_path)
	{
		return last_error_or(ERROR_INVALID_NAME);
	}
	progress_event(ctx, WOFMNT_PROGRESS_WRITING_ADS, stream_path, NULL);
	file = CreateFileW(
		stream_path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | (parent_is_directory ? FILE_FLAG_BACKUP_SEMANTICS : 0),
		NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		err = last_error_or(ERROR_CREATE_FAILED);
		free(stream_path);
		return err;
	}
	err = wim_extract_hash_to_handle(ctx, stream->hash, file);
	CloseHandle(file);
	free(stream_path);
	if (err == ERROR_SUCCESS && ctx->stats)
	{
		ctx->stats->ads_streams_materialized++;
	}
	return err;
}

static DWORD materialize_named_streams(APPLY_CONTEXT *ctx, const wchar_t *path, WIM_DENTRY *entry, bool parent_is_directory)
{
	for (size_t i = 0; i < entry->num_streams; ++i)
	{
		if (entry->streams[i].kind == STREAM_KIND_DATA && entry->streams[i].name)
		{
			DWORD err = materialize_named_stream(ctx, path, &entry->streams[i], parent_is_directory);
			if (err != ERROR_SUCCESS)
			{
				return err;
			}
		}
	}
	return ERROR_SUCCESS;
}

static DWORD create_reparse_point(APPLY_CONTEXT *ctx, const wchar_t *path, WIM_DENTRY *entry, bool is_directory)
{
	WIM_STREAM *reparse_stream = find_stream(entry, STREAM_KIND_REPARSE, false);
	BYTE *reparse_data = NULL;
	BYTE *reparse_buffer = NULL;
	size_t reparse_data_size = 0;
	DWORD input_size;
	HANDLE file;
	DWORD bytes_returned = 0;
	DWORD err;
	REPARSE_BUFFER_HEADER_DISK *header;

	if (!reparse_stream)
	{
		return ERROR_INVALID_DATA;
	}
	err = wim_extract_hash_alloc(
		ctx,
		reparse_stream->hash,
		REPARSE_POINT_MAX_SIZE - REPARSE_DATA_OFFSET,
		&reparse_data,
		&reparse_data_size);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}

	reparse_buffer = (BYTE *)calloc(1u, REPARSE_POINT_MAX_SIZE);
	if (!reparse_buffer)
	{
		free(reparse_data);
		return ERROR_OUTOFMEMORY;
	}
	header = (REPARSE_BUFFER_HEADER_DISK *)reparse_buffer;
	header->reparse_tag = entry->reparse_tag;
	header->reparse_reserved = entry->rp_reserved;
	if ((entry->reparse_tag & 0x80000000UL) == 0 && reparse_data_size >= sizeof(GUID))
	{
		header->reparse_data_length = (uint16_t)(reparse_data_size - sizeof(GUID));
	}
	else
	{
		header->reparse_data_length = (uint16_t)reparse_data_size;
	}
	memcpy(reparse_buffer + REPARSE_DATA_OFFSET, reparse_data, reparse_data_size);
	input_size = (DWORD)(REPARSE_DATA_OFFSET + reparse_data_size);

	file = CreateFileW(
		path,
		GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | (is_directory ? FILE_FLAG_BACKUP_SEMANTICS : 0),
		NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		err = last_error_or(ERROR_OPEN_FAILED);
	}
	else if (!DeviceIoControl(file, FSCTL_SET_REPARSE_POINT, reparse_buffer, input_size, NULL, 0, &bytes_returned, NULL))
	{
		err = last_error_or(ERROR_ACCESS_DENIED);
	}
	else
	{
		err = ERROR_SUCCESS;
	}
	if (file != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file);
	}
	free(reparse_data);
	free(reparse_buffer);
	if (err == ERROR_SUCCESS && ctx->stats)
	{
		ctx->stats->reparse_points_created++;
	}
	return err;
}

static DWORD create_regular_file(APPLY_CONTEXT *ctx, const wchar_t *path, WIM_DENTRY *entry, bool *created_primary)
{
	WIM_STREAM *data_stream = find_stream(entry, STREAM_KIND_DATA, false);
	WIM_STREAM *efs_stream = find_stream(entry, STREAM_KIND_EFS_RAW, false);
	HANDLE file;
	DWORD err;

	*created_primary = false;
	if (!data_stream && efs_stream)
	{
		progress_event(ctx, WOFMNT_PROGRESS_WARNING, path, L"encrypted raw data is being materialized as a regular stream");
		data_stream = efs_stream;
	}

	progress_event(ctx, WOFMNT_PROGRESS_CREATING_FILE, path, NULL);
	file = create_file_for_write(path, CREATE_NEW, 0);
	if (file == INVALID_HANDLE_VALUE)
	{
		return last_error_or(ERROR_CREATE_FAILED);
	}
	*created_primary = true;
	if (ctx->stats)
	{
		ctx->stats->files_created++;
	}

	if (!data_stream || data_stream->size == 0 || hash_is_zero(data_stream->hash))
	{
		CloseHandle(file);
		if (ctx->stats)
		{
			ctx->stats->empty_files_created++;
		}
		return materialize_named_streams(ctx, path, entry, false);
	}

	err = WofMntSetWimExternalBacking(file, ctx->data_source_id, data_stream->hash);
	if (err == ERROR_SUCCESS)
	{
		CloseHandle(file);
		if (ctx->stats)
		{
			ctx->stats->wof_files_created++;
		}
		return materialize_named_streams(ctx, path, entry, false);
	}

	if ((ctx->flags & WOFMNT_MOUNT_FLAG_MATERIALIZE_ON_WOF_FAIL) == 0)
	{
		CloseHandle(file);
		return err;
	}

	progress_event(ctx, WOFMNT_PROGRESS_WARNING, path, L"WOF backing failed; materializing file data");
	err = wim_extract_hash_to_handle(ctx, data_stream->hash, file);
	CloseHandle(file);
	if (err == ERROR_SUCCESS && ctx->stats)
	{
		ctx->stats->files_materialized++;
	}
	if (err != ERROR_SUCCESS)
	{
		return err;
	}
	return materialize_named_streams(ctx, path, entry, false);
}

static DWORD create_reparse_entry(APPLY_CONTEXT *ctx, const wchar_t *path, WIM_DENTRY *entry, bool is_directory)
{
	WIM_STREAM *data_stream;
	DWORD err;

	progress_event(ctx, WOFMNT_PROGRESS_CREATING_REPARSE_POINT, path, NULL);
	if (is_directory)
	{
		if (!CreateDirectoryW(path, NULL))
		{
			return last_error_or(ERROR_CREATE_FAILED);
		}
		if (ctx->stats)
		{
			ctx->stats->directories_created++;
		}
	}
	else
	{
		HANDLE file = create_file_for_write(path, CREATE_NEW, 0);
		if (file == INVALID_HANDLE_VALUE)
		{
			return last_error_or(ERROR_CREATE_FAILED);
		}
		CloseHandle(file);
		if (ctx->stats)
		{
			ctx->stats->files_created++;
		}
	}

	err = apply_security(ctx, path, entry->security_id);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}

	data_stream = find_stream(entry, STREAM_KIND_DATA, false);
	if (data_stream && !is_directory && !hash_is_zero(data_stream->hash))
	{
		err = materialize_hash_to_file(ctx, data_stream->hash, path, OPEN_EXISTING);
		if (err != ERROR_SUCCESS)
		{
			return err;
		}
	}
	err = materialize_named_streams(ctx, path, entry, is_directory);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}
	err = create_reparse_point(ctx, path, entry, is_directory);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}
	return apply_times_and_attributes(path, entry);
}

static DWORD apply_directory_children(APPLY_CONTEXT *ctx, size_t directory_offset, const wchar_t *directory_path);

static DWORD apply_directory_entry(APPLY_CONTEXT *ctx, const wchar_t *path, WIM_DENTRY *entry)
{
	DWORD err;

	progress_event(ctx, WOFMNT_PROGRESS_CREATING_DIRECTORY, path, NULL);
	if (!CreateDirectoryW(path, NULL))
	{
		return last_error_or(ERROR_CREATE_FAILED);
	}
	if (ctx->stats)
	{
		ctx->stats->directories_created++;
	}
	err = apply_security(ctx, path, entry->security_id);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}
	if (entry->subdir_offset != 0)
	{
		size_t child_offset;
		if (!checked_size_from_u64(entry->subdir_offset, &child_offset) || child_offset >= ctx->metadata_size)
		{
			return ERROR_INVALID_DATA;
		}
		err = apply_directory_children(ctx, child_offset, path);
		if (err != ERROR_SUCCESS)
		{
			return err;
		}
	}
	return apply_times_and_attributes(path, entry);
}

static DWORD apply_file_entry(APPLY_CONTEXT *ctx, const wchar_t *path, WIM_DENTRY *entry)
{
	const wchar_t *first_path = NULL;
	bool created_primary = false;
	DWORD err;

	if (entry->hard_link_group_id != 0 &&
		hard_link_lookup(&ctx->hard_links, entry->hard_link_group_id, &first_path) == ERROR_SUCCESS &&
		first_path)
	{
		progress_event(ctx, WOFMNT_PROGRESS_CREATING_HARDLINK, path, first_path);
		if (!CreateHardLinkW(path, first_path, NULL))
		{
			return last_error_or(ERROR_CREATE_FAILED);
		}
		if (ctx->stats)
		{
			ctx->stats->hard_links_created++;
		}
		err = apply_security(ctx, path, entry->security_id);
		if (err != ERROR_SUCCESS)
		{
			return err;
		}
		return apply_times_and_attributes(path, entry);
	}

	err = create_regular_file(ctx, path, entry, &created_primary);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}
	if (created_primary && entry->hard_link_group_id != 0)
	{
		err = hard_link_add(&ctx->hard_links, entry->hard_link_group_id, path);
		if (err != ERROR_SUCCESS)
		{
			return err;
		}
	}
	err = apply_security(ctx, path, entry->security_id);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}
	return apply_times_and_attributes(path, entry);
}

static DWORD apply_entry(APPLY_CONTEXT *ctx, const wchar_t *parent_path, WIM_DENTRY *entry)
{
	bool is_directory = (entry->attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
	bool is_reparse = (entry->attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
	wchar_t *child_path;
	DWORD err;

	if (!entry->name || entry->name[0] == L'\0')
	{
		return ERROR_INVALID_DATA;
	}
	child_path = make_child_path(parent_path, entry->name);
	if (!child_path)
	{
		return last_error_or(ERROR_INVALID_NAME);
	}
	if (is_reparse)
	{
		err = create_reparse_entry(ctx, child_path, entry, is_directory);
	}
	else if (is_directory)
	{
		err = apply_directory_entry(ctx, child_path, entry);
	}
	else
	{
		err = apply_file_entry(ctx, child_path, entry);
	}
	free(child_path);
	return err;
}

static DWORD apply_directory_children(APPLY_CONTEXT *ctx, size_t directory_offset, const wchar_t *directory_path)
{
	size_t offset = directory_offset;

	while (true)
	{
		WIM_DENTRY entry;
		size_t next_offset = 0;
		bool is_terminator = false;
		DWORD err = parse_dentry_at(ctx, offset, &entry, &next_offset, &is_terminator);
		if (err != ERROR_SUCCESS)
		{
			return err;
		}
		if (is_terminator)
		{
			return ERROR_SUCCESS;
		}
		assign_stream_kinds(&entry);
		err = resolve_stream_resources(ctx, &entry);
		if (err == ERROR_SUCCESS)
		{
			err = apply_entry(ctx, directory_path, &entry);
		}
		free_dentry(&entry);
		if (err != ERROR_SUCCESS)
		{
			return err;
		}
		if (next_offset <= offset || next_offset > ctx->metadata_size)
		{
			return ERROR_INVALID_DATA;
		}
		offset = next_offset;
	}
}

static DWORD apply_image_root(APPLY_CONTEXT *ctx)
{
	WIM_DENTRY root_entry;
	bool is_terminator = false;
	size_t root_offset = ctx->security.total_length;
	size_t next_offset = 0;
	size_t child_offset;
	DWORD err;

	if (root_offset >= ctx->metadata_size)
	{
		return ERROR_INVALID_DATA;
	}
	err = parse_dentry_at(ctx, root_offset, &root_entry, &next_offset, &is_terminator);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}
	if (!is_terminator && root_entry.name && root_entry.name[0] == L'\0' && root_entry.subdir_offset != 0)
	{
		child_offset = (size_t)root_entry.subdir_offset;
		err = apply_security(ctx, ctx->target_path, root_entry.security_id);
		if (err == ERROR_SUCCESS)
		{
			err = apply_directory_children(ctx, child_offset, ctx->target_path);
		}
		if (err == ERROR_SUCCESS)
		{
			err = apply_times_and_attributes(ctx->target_path, &root_entry);
		}
		free_dentry(&root_entry);
		return err;
	}
	free_dentry(&root_entry);
	return apply_directory_children(ctx, root_offset, ctx->target_path);
}

static DWORD delete_tree_contents(const wchar_t *directory_path)
{
	wchar_t *pattern = make_child_path(directory_path, L"*");
	WIN32_FIND_DATAW data;
	HANDLE find_handle;
	DWORD err = ERROR_SUCCESS;

	if (!pattern)
	{
		return last_error_or(ERROR_INVALID_NAME);
	}
	find_handle = FindFirstFileW(pattern, &data);
	free(pattern);
	if (find_handle == INVALID_HANDLE_VALUE)
	{
		err = last_error_or(ERROR_FILE_NOT_FOUND);
		return err == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : err;
	}
	do
	{
		wchar_t *child_path;
		if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
		{
			continue;
		}
		child_path = make_child_path(directory_path, data.cFileName);
		if (!child_path)
		{
			err = last_error_or(ERROR_INVALID_NAME);
			break;
		}
		(void)SetFileAttributesW(child_path, FILE_ATTRIBUTE_NORMAL);
		if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
			(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
		{
			err = delete_tree_contents(child_path);
			if (err == ERROR_SUCCESS && !RemoveDirectoryW(child_path))
			{
				err = last_error_or(ERROR_ACCESS_DENIED);
			}
		}
		else if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
		{
			if (!RemoveDirectoryW(child_path))
			{
				err = last_error_or(ERROR_ACCESS_DENIED);
			}
		}
		else if (!DeleteFileW(child_path))
		{
			err = last_error_or(ERROR_ACCESS_DENIED);
		}
		free(child_path);
		if (err != ERROR_SUCCESS)
		{
			break;
		}
	} while (FindNextFileW(find_handle, &data));
	if (err == ERROR_SUCCESS && GetLastError() != ERROR_NO_MORE_FILES)
	{
		err = last_error_or(ERROR_READ_FAULT);
	}
	FindClose(find_handle);
	return err;
}

DWORD WofMntGetWimInfo(const wchar_t *wim_path, WOFMNT_WIM_INFO *info)
{
	WIM_FILE wim;
	DWORD err = ERROR_SUCCESS;

	ZeroMemory(&wim, sizeof(wim));

	if (!wim_path || !info)
	{
		err = ERROR_INVALID_PARAMETER;
		goto out;
	}
	err = wim_open(wim_path, &wim);
	if (err != ERROR_SUCCESS)
	{
		goto out;
	}
	ZeroMemory(info, sizeof(*info));
	info->image_count = wim.header.image_count;
	info->boot_index = wim.header.boot_index;
	info->compression_flags = wim.header.flags & (WIM_HDR_FLAG_XPRESS | WIM_HDR_FLAG_LZX | WIM_HDR_FLAG_LZMS);
	info->chunk_size = wim.header.chunk_size;
	memcpy(&info->guid, wim.header.guid, sizeof(info->guid));

out:
	wim_close(&wim);
	return err;
}

DWORD WofMntMountWim(
	const wchar_t *wim_path,
	uint32_t image_index,
	const wchar_t *target_directory,
	const WOFMNT_OPTIONS *options,
	WOFMNT_MOUNT_STATS *stats)
{
	WIM_FILE wim;
	APPLY_CONTEXT ctx;
	WOFMNT_OPTIONS default_options;
	wchar_t *target_io_path = NULL;
	wchar_t *wim_full_path = NULL;
	DWORD err = ERROR_SUCCESS;
	uint32_t wim_type;

	ZeroMemory(&wim, sizeof(wim));
	ZeroMemory(&ctx, sizeof(ctx));

	if (!wim_path || !target_directory || image_index == 0)
	{
		err = ERROR_INVALID_PARAMETER;
		goto out;
	}
	if (!options)
	{
		ZeroMemory(&default_options, sizeof(default_options));
		default_options.size = sizeof(default_options);
		options = &default_options;
	}
	if (options->size != 0 && options->size < sizeof(WOFMNT_OPTIONS))
	{
		err = ERROR_INVALID_PARAMETER;
		goto out;
	}
	if (stats)
	{
		ZeroMemory(stats, sizeof(*stats));
	}

	enable_best_effort_privileges();
	err = validate_target_directory(target_directory);
	if (err != ERROR_SUCCESS)
	{
		goto out;
	}

	target_io_path = normalize_path_for_io(target_directory);
	wim_full_path = make_full_path_no_prefix(wim_path);
	if (!target_io_path || !wim_full_path)
	{
		err = last_error_or(ERROR_INVALID_PARAMETER);
		goto out;
	}

	progress_event(NULL, WOFMNT_PROGRESS_SCANNING_WIM, wim_path, NULL);
	err = wim_open(wim_path, &wim);
	if (err != ERROR_SUCCESS)
	{
		goto out;
	}
	err = wim_load_lookup_table(&wim);
	if (err != ERROR_SUCCESS)
	{
		goto out;
	}
	if (image_index > wim.metadata_count)
	{
		err = ERROR_INVALID_INDEX;
		goto out;
	}

	ctx.wim = &wim;
	ctx.target_path = target_io_path;
	ctx.wim_path = wim_full_path;
	ctx.image_index = image_index;
	ctx.flags = options->flags;
	ctx.progress = options->progress;
	ctx.progress_context = options->progress_context;
	ctx.stats = stats;

	progress_event(&ctx, WOFMNT_PROGRESS_SCANNING_WIM, wim_path, L"reading image metadata");
	err = wim_read_resource_alloc(&wim, &wim.metadata_resources[(size_t)image_index - 1u], &ctx.metadata, &ctx.metadata_size);
	if (err != ERROR_SUCCESS)
	{
		goto out;
	}
	progress_event(&ctx, WOFMNT_PROGRESS_SCANNING_WIM, wim_path, L"image metadata decompressed");
	err = read_security_table(ctx.metadata, ctx.metadata_size, &ctx.security);
	if (err != ERROR_SUCCESS)
	{
		goto out;
	}
	progress_event(&ctx, WOFMNT_PROGRESS_SCANNING_WIM, wim_path, L"security table parsed");

	progress_event(&ctx, WOFMNT_PROGRESS_REGISTERING_WIM, target_directory, wim_path);
	wim_type = (options->flags & WOFMNT_MOUNT_FLAG_OS_WIM) != 0 ? WIM_BOOT_OS_WIM : WIM_BOOT_NOT_OS_WIM;
	err = WofMntRegisterWimDataSource(target_directory, wim_path, image_index, wim_type, &ctx.data_source_id);
	if (err != ERROR_SUCCESS)
	{
		goto out;
	}
	if (stats)
	{
		stats->data_source_id = ctx.data_source_id;
	}

	err = apply_image_root(&ctx);
	if (err != ERROR_SUCCESS)
	{
		goto out;
	}
	err = create_manifest(target_io_path, wim_path, image_index, ctx.data_source_id);

out:
	free_hard_link_table(&ctx.hard_links);
	free_security_table(&ctx.security);
	free(ctx.metadata);
	wim_close(&wim);
	free(target_io_path);
	free(wim_full_path);
	return err;
}

DWORD WofMntUnmount(
	const wchar_t *target_directory,
	const WOFMNT_OPTIONS *options)
{
	wchar_t *target_io_path = NULL;
	LARGE_INTEGER data_source_id;
	bool have_manifest;
	DWORD err = ERROR_SUCCESS;
	DWORD remove_err = ERROR_SUCCESS;

	(void)options;
	if (!target_directory)
	{
		err = ERROR_INVALID_PARAMETER;
		goto out;
	}
	enable_best_effort_privileges();
	target_io_path = normalize_path_for_io(target_directory);
	if (!target_io_path)
	{
		err = last_error_or(ERROR_INVALID_PARAMETER);
		goto out;
	}

	err = read_manifest(target_io_path, &data_source_id);
	have_manifest = (err == ERROR_SUCCESS);

	err = delete_tree_contents(target_io_path);
	if (err == ERROR_SUCCESS && have_manifest)
	{
		remove_err = WofMntRemoveWimDataSource(target_directory, data_source_id);
		if (remove_err != ERROR_SUCCESS)
		{
			err = remove_err;
		}
	}
out:
	free(target_io_path);
	return err;
}

const wchar_t *WofMntVersionString(void)
{
	return L"wofmnt 0.1";
}
