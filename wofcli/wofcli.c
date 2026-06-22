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

#include <Windows.h>
#include <woflib.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define OPTPARSE_IMPLEMENTATION
#include "optparse.h"

static void print_usage(void)
{
	fwprintf(stderr, L"%ls\n", WofMntVersionString());
	fwprintf(stderr, L"Copyright (C) 2026 A1ive <https://a1ive.github.io/>.\n");
	fwprintf(stderr, L"Usage:\n");
	fwprintf(stderr, L"  wofcli info <wim>\n");
	fwprintf(stderr, L"  wofcli mount <wim> <empty-ntfs-dir> [--index N] [--os-wim] [--no-acl] [--strict-acl] [--materialize-on-wof-fail]\n");
	fwprintf(stderr, L"  wofcli unmount <dir>\n");
}

static DWORD last_error_or(DWORD fallback)
{
	DWORD err = GetLastError();

	if (err == ERROR_SUCCESS)
	{
		err = fallback;
	}
	return err;
}

static void print_error(DWORD err)
{
	fprintf(stderr, "error %lu\n", err);
}

static void print_option_error(const struct optparse *parser)
{
	if (parser->errmsg[0] != '\0')
	{
		fprintf(stderr, "%s\n", parser->errmsg);
	}
	else
	{
		fprintf(stderr, "invalid option\n");
	}
}

static bool parse_u32_arg(const char *text, uint32_t *value)
{
	char *end = NULL;
	unsigned long parsed;

	if (!text || !text[0] || text[0] == '-' || text[0] == '+')
	{
		return false;
	}

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno == ERANGE || !end || *end != '\0' || parsed == 0 || parsed > UINT32_MAX)
	{
		return false;
	}

	*value = (uint32_t)parsed;
	return true;
}

static DWORD wide_to_utf8(const wchar_t *text, char **utf8)
{
	char *buffer = NULL;
	int required;
	DWORD err = ERROR_SUCCESS;

	if (!text || !utf8)
	{
		err = ERROR_INVALID_PARAMETER;
		goto out;
	}

	*utf8 = NULL;
	required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, NULL, 0, NULL, NULL);
	if (required <= 0)
	{
		err = last_error_or(ERROR_NO_UNICODE_TRANSLATION);
		goto out;
	}

	buffer = (char *)calloc((size_t)required, sizeof(char));
	if (!buffer)
	{
		err = ERROR_OUTOFMEMORY;
		goto out;
	}

	if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, buffer, required, NULL, NULL) <= 0)
	{
		err = last_error_or(ERROR_NO_UNICODE_TRANSLATION);
		goto out;
	}

	*utf8 = buffer;
	buffer = NULL;

out:
	free(buffer);
	return err;
}

static DWORD utf8_to_wide(const char *text, wchar_t **wide)
{
	wchar_t *buffer = NULL;
	int required;
	DWORD err = ERROR_SUCCESS;

	if (!text || !wide)
	{
		err = ERROR_INVALID_PARAMETER;
		goto out;
	}

	*wide = NULL;
	required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
	if (required <= 0)
	{
		err = last_error_or(ERROR_NO_UNICODE_TRANSLATION);
		goto out;
	}

	buffer = (wchar_t *)calloc((size_t)required, sizeof(wchar_t));
	if (!buffer)
	{
		err = ERROR_OUTOFMEMORY;
		goto out;
	}

	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, buffer, required) <= 0)
	{
		err = last_error_or(ERROR_NO_UNICODE_TRANSLATION);
		goto out;
	}

	*wide = buffer;
	buffer = NULL;

out:
	free(buffer);
	return err;
}

static void free_argv_utf8(int argc, char **argv)
{
	if (argv)
	{
		for (int i = 0; i < argc; ++i)
		{
			free(argv[i]);
		}
		free(argv);
	}
}

static DWORD argv_wide_to_utf8(int argc, wchar_t **wargv, char ***argv_out)
{
	char **argv = NULL;
	DWORD err = ERROR_SUCCESS;

	if (argc < 0 || !wargv || !argv_out)
	{
		err = ERROR_INVALID_PARAMETER;
		goto out;
	}

	*argv_out = NULL;
	argv = (char **)calloc((size_t)argc + 1u, sizeof(char *));
	if (!argv)
	{
		err = ERROR_OUTOFMEMORY;
		goto out;
	}

	for (int i = 0; i < argc; ++i)
	{
		err = wide_to_utf8(wargv[i], &argv[i]);
		if (err != ERROR_SUCCESS)
		{
			goto out;
		}
	}

	*argv_out = argv;
	argv = NULL;

out:
	free_argv_utf8(argc, argv);
	return err;
}

static DWORD resolve_default_image_index(const wchar_t *wim_path, uint32_t *image_index)
{
	WOFMNT_WIM_INFO info;
	DWORD err;

	if (!wim_path || !image_index)
	{
		err = ERROR_INVALID_PARAMETER;
		goto out;
	}

	err = WofMntGetWimInfo(wim_path, &info);
	if (err != ERROR_SUCCESS)
	{
		goto out;
	}

	if (info.image_count == 0)
	{
		err = ERROR_INVALID_DATA;
		goto out;
	}

	if (info.boot_index != 0)
	{
		if (info.boot_index > info.image_count)
		{
			err = ERROR_INVALID_INDEX;
			goto out;
		}
		*image_index = info.boot_index;
	}
	else
	{
		*image_index = 1u;
	}

	err = ERROR_SUCCESS;

out:
	return err;
}

static void CALLBACK progress_callback(
	WOFMNT_PROGRESS_EVENT event_id,
	const wchar_t *path,
	const wchar_t *detail,
	void *user_context)
{
	const wchar_t *trace = _wgetenv(L"WOFMNT_TRACE");
	(void)user_context;
	if (event_id == WOFMNT_PROGRESS_WARNING)
	{
		fwprintf(stderr, L"warning: %ls", detail ? detail : L"operation warning");
		if (path)
		{
			fwprintf(stderr, L": %ls", path);
		}
		fwprintf(stderr, L"\n");
	}
	else if (trace && trace[0] != L'\0' && wcscmp(trace, L"0") != 0)
	{
		fwprintf(stderr, L"trace[%u]", (unsigned)event_id);
		if (detail)
		{
			fwprintf(stderr, L" %ls", detail);
		}
		if (path)
		{
			fwprintf(stderr, L": %ls", path);
		}
		fwprintf(stderr, L"\n");
	}
}

static int command_info(int argc, char **argv)
{
	static const struct optparse_option longopts[] = {
		{0, 0, 0},
	};
	struct optparse parser;
	WOFMNT_WIM_INFO info;
	wchar_t *wim_path = NULL;
	char *wim_arg;
	DWORD err;
	int opt;
	int rc = 0;

	optparse_init(&parser, argv);
	while ((opt = optparse(&parser, longopts, NULL)) != OPTPARSE_DONE)
	{
		if (opt == OPTPARSE_ERR)
		{
			print_option_error(&parser);
			rc = 2;
			goto out;
		}
	}

	wim_arg = optparse_arg(&parser);
	if (!wim_arg || optparse_arg(&parser))
	{
		print_usage();
		rc = 2;
		goto out;
	}

	err = utf8_to_wide(wim_arg, &wim_path);
	if (err != ERROR_SUCCESS)
	{
		print_error(err);
		rc = 1;
		goto out;
	}

	err = WofMntGetWimInfo(wim_path, &info);
	if (err != ERROR_SUCCESS)
	{
		print_error(err);
		rc = 1;
		goto out;
	}
	wprintf(L"Images: %u\n", info.image_count);
	if (info.boot_index != 0)
	{
		wprintf(L"Boot index: %u\n", info.boot_index);
	}
	else
	{
		wprintf(L"Boot index: none\n");
	}
	wprintf(L"Chunk size: %u\n", info.chunk_size);
	wprintf(L"Compression flags: 0x%08x\n", info.compression_flags);
	wprintf(
		L"GUID: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
		info.guid.Data1,
		info.guid.Data2,
		info.guid.Data3,
		info.guid.Data4[0],
		info.guid.Data4[1],
		info.guid.Data4[2],
		info.guid.Data4[3],
		info.guid.Data4[4],
		info.guid.Data4[5],
		info.guid.Data4[6],
		info.guid.Data4[7]);

out:
	free(wim_path);
	return rc;
}

static int command_mount(int argc, char **argv)
{
	enum
	{
		OPT_INDEX,
		OPT_OS_WIM,
		OPT_NO_ACL,
		OPT_STRICT_ACL,
		OPT_MATERIALIZE_ON_WOF_FAIL
	};
	static const struct optparse_option longopts[] = {
		{"index", 0, OPTPARSE_REQUIRED},
		{"os-wim", 0, OPTPARSE_NONE},
		{"no-acl", 0, OPTPARSE_NONE},
		{"strict-acl", 0, OPTPARSE_NONE},
		{"materialize-on-wof-fail", 0, OPTPARSE_NONE},
		{0, 0, 0},
	};
	struct optparse parser;
	WOFMNT_OPTIONS options;
	WOFMNT_MOUNT_STATS stats;
	wchar_t *wim_path = NULL;
	wchar_t *target_path = NULL;
	char *wim_arg;
	char *target_arg;
	uint32_t image_index = 0;
	bool index_specified = false;
	DWORD err;
	int opt;
	int rc = 0;

	ZeroMemory(&options, sizeof(options));
	options.size = sizeof(options);
	options.progress = progress_callback;

	optparse_init(&parser, argv);
	while ((opt = optparse(&parser, longopts, NULL)) != OPTPARSE_DONE)
	{
		if (opt == OPTPARSE_ERR)
		{
			print_option_error(&parser);
			rc = 2;
			goto out;
		}

		switch (opt)
		{
		case OPT_INDEX:
			if (index_specified)
			{
				fprintf(stderr, "duplicate option: --index\n");
				rc = 2;
				goto out;
			}
			if (!parse_u32_arg(parser.optarg, &image_index))
			{
				fprintf(stderr, "invalid image index: %s\n", parser.optarg ? parser.optarg : "");
				rc = 2;
				goto out;
			}
			index_specified = true;
			break;
		case OPT_OS_WIM:
			options.flags |= WOFMNT_MOUNT_FLAG_OS_WIM;
			break;
		case OPT_NO_ACL:
			options.flags |= WOFMNT_MOUNT_FLAG_DISABLE_ACLS;
			break;
		case OPT_STRICT_ACL:
			options.flags |= WOFMNT_MOUNT_FLAG_STRICT_ACLS;
			break;
		case OPT_MATERIALIZE_ON_WOF_FAIL:
			options.flags |= WOFMNT_MOUNT_FLAG_MATERIALIZE_ON_WOF_FAIL;
			break;
		default:
			fprintf(stderr, "invalid option\n");
			rc = 2;
			goto out;
		}
	}

	wim_arg = optparse_arg(&parser);
	target_arg = optparse_arg(&parser);
	if (!wim_arg || !target_arg || optparse_arg(&parser))
	{
		print_usage();
		rc = 2;
		goto out;
	}

	err = utf8_to_wide(wim_arg, &wim_path);
	if (err != ERROR_SUCCESS)
	{
		print_error(err);
		rc = 1;
		goto out;
	}
	err = utf8_to_wide(target_arg, &target_path);
	if (err != ERROR_SUCCESS)
	{
		print_error(err);
		rc = 1;
		goto out;
	}

	if (!index_specified)
	{
		err = resolve_default_image_index(wim_path, &image_index);
		if (err != ERROR_SUCCESS)
		{
			print_error(err);
			rc = 1;
			goto out;
		}
	}

	err = WofMntMountWim(wim_path, image_index, target_path, &options, &stats);
	if (err != ERROR_SUCCESS)
	{
		print_error(err);
		rc = 1;
		goto out;
	}

	wprintf(L"Mounted image %u\n", image_index);
	wprintf(L"DataSourceId: %lld\n", stats.data_source_id.QuadPart);
	wprintf(L"Directories: %llu\n", (unsigned long long)stats.directories_created);
	wprintf(L"Files: %llu\n", (unsigned long long)stats.files_created);
	wprintf(L"WOF files: %llu\n", (unsigned long long)stats.wof_files_created);
	wprintf(L"Empty files: %llu\n", (unsigned long long)stats.empty_files_created);
	wprintf(L"Hard links: %llu\n", (unsigned long long)stats.hard_links_created);
	wprintf(L"Reparse points: %llu\n", (unsigned long long)stats.reparse_points_created);
	wprintf(L"ADS materialized: %llu\n", (unsigned long long)stats.ads_streams_materialized);
	wprintf(L"Materialized files: %llu\n", (unsigned long long)stats.files_materialized);
	wprintf(L"ACL failures: %llu\n", (unsigned long long)stats.security_descriptor_failures);
	wprintf(L"Warnings: %llu\n", (unsigned long long)stats.warnings);

out:
	free(target_path);
	free(wim_path);
	return rc;
}

static int command_unmount(int argc, char **argv)
{
	static const struct optparse_option longopts[] = {
		{0, 0, 0},
	};
	struct optparse parser;
	wchar_t *target_path = NULL;
	char *target_arg;
	DWORD err;
	int opt;
	int rc = 0;

	optparse_init(&parser, argv);
	while ((opt = optparse(&parser, longopts, NULL)) != OPTPARSE_DONE)
	{
		if (opt == OPTPARSE_ERR)
		{
			print_option_error(&parser);
			rc = 2;
			goto out;
		}
	}

	target_arg = optparse_arg(&parser);
	if (!target_arg || optparse_arg(&parser))
	{
		print_usage();
		rc = 2;
		goto out;
	}

	err = utf8_to_wide(target_arg, &target_path);
	if (err != ERROR_SUCCESS)
	{
		print_error(err);
		rc = 1;
		goto out;
	}

	err = WofMntUnmount(target_path, NULL);
	if (err != ERROR_SUCCESS)
	{
		print_error(err);
		rc = 1;
		goto out;
	}
	wprintf(L"Unmounted: %ls\n", target_path);

out:
	free(target_path);
	return rc;
}

int wmain(int argc, wchar_t **wargv)
{
	char **argv = NULL;
	DWORD err;
	int rc = 0;

	err = argv_wide_to_utf8(argc, wargv, &argv);
	if (err != ERROR_SUCCESS)
	{
		print_error(err);
		rc = 1;
		goto out;
	}

	if (argc < 2)
	{
		print_usage();
		rc = 2;
		goto out;
	}
	if (_stricmp(argv[1], "info") == 0)
	{
		rc = command_info(argc - 1, argv + 1);
		goto out;
	}
	if (_stricmp(argv[1], "mount") == 0)
	{
		rc = command_mount(argc - 1, argv + 1);
		goto out;
	}
	if (_stricmp(argv[1], "unmount") == 0)
	{
		rc = command_unmount(argc - 1, argv + 1);
		goto out;
	}
	print_usage();
	rc = 2;

out:
	free_argv_utf8(argc, argv);
	return rc;
}
