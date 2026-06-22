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

#include <Windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define WOFMNT_API_VERSION 1u

#define WOFMNT_MOUNT_FLAG_OS_WIM 0x00000001u
#define WOFMNT_MOUNT_FLAG_DISABLE_ACLS 0x00000002u
#define WOFMNT_MOUNT_FLAG_STRICT_ACLS 0x00000004u
#define WOFMNT_MOUNT_FLAG_MATERIALIZE_FALLBACK 0x00000008u

	typedef enum WOFMNT_PROGRESS_EVENT
	{
		WOFMNT_PROGRESS_SCANNING_WIM = 1,
		WOFMNT_PROGRESS_REGISTERING_WIM = 2,
		WOFMNT_PROGRESS_CREATING_DIRECTORY = 3,
		WOFMNT_PROGRESS_CREATING_FILE = 4,
		WOFMNT_PROGRESS_CREATING_HARDLINK = 5,
		WOFMNT_PROGRESS_CREATING_REPARSE_POINT = 6,
		WOFMNT_PROGRESS_WRITING_ADS = 7,
		WOFMNT_PROGRESS_WARNING = 8
	} WOFMNT_PROGRESS_EVENT;

	typedef void(CALLBACK *WOFMNT_PROGRESS_CALLBACK)(
		WOFMNT_PROGRESS_EVENT event_id,
		const wchar_t *path,
		const wchar_t *detail,
		void *user_context);

	typedef struct WOFMNT_OPTIONS
	{
		uint32_t size;
		uint32_t flags;
		WOFMNT_PROGRESS_CALLBACK progress;
		void *progress_context;
	} WOFMNT_OPTIONS;

	typedef struct WOFMNT_MOUNT_STATS
	{
		uint64_t directories_created;
		uint64_t files_created;
		uint64_t empty_files_created;
		uint64_t wof_files_created;
		uint64_t hard_links_created;
		uint64_t reparse_points_created;
		uint64_t ads_streams_materialized;
		uint64_t files_materialized;
		uint64_t security_descriptors_applied;
		uint64_t security_descriptor_failures;
		uint64_t warnings;
		LARGE_INTEGER data_source_id;
	} WOFMNT_MOUNT_STATS;

	typedef struct WOFMNT_WIM_INFO
	{
		uint32_t image_count;
		uint32_t boot_index;
		uint32_t compression_flags;
		uint32_t chunk_size;
		GUID guid;
	} WOFMNT_WIM_INFO;

	DWORD WofMntGetWimInfo(
		const wchar_t *wim_path,
		WOFMNT_WIM_INFO *info);

	DWORD WofMntMountWim(
		const wchar_t *wim_path,
		uint32_t image_index,
		const wchar_t *target_directory,
		const WOFMNT_OPTIONS *options,
		WOFMNT_MOUNT_STATS *stats);

	DWORD WofMntUnmount(
		const wchar_t *target_directory,
		const WOFMNT_OPTIONS *options);

	DWORD WofMntRegisterWimDataSource(
		const wchar_t *target_directory,
		const wchar_t *wim_path,
		uint32_t image_index,
		uint32_t wim_type,
		LARGE_INTEGER *data_source_id);

	DWORD WofMntRemoveWimDataSource(
		const wchar_t *target_directory,
		LARGE_INTEGER data_source_id);

	DWORD WofMntSetWimExternalBacking(
		HANDLE file_handle,
		LARGE_INTEGER data_source_id,
		const BYTE resource_hash[20]);

	const wchar_t *WofMntVersionString(void);

#ifdef __cplusplus
}
#endif
