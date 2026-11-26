import {
  FILE_STATES,
  SHARE_STATUSES,
  type ActivityItem,
  type ActivityList,
  type FileFeatureStatus,
  type FileList,
  type PublicShareInfo,
  type Share,
  type ShareCreated,
  type StoredFile,
  type StoredFileDetail,
} from "../types/files";
import {
  isArrayOf,
  isCount,
  isNullableString,
  isOneOf,
  isRecord,
  isString,
} from "./guardPrimitives";

const isShareStatus = isOneOf(SHARE_STATUSES);
const isFileState = isOneOf(FILE_STATES);

export function isFileFeatureStatus(value: unknown): value is FileFeatureStatus {
  return (
    isRecord(value) &&
    typeof value.configured === "boolean" &&
    isCount(value.max_file_size_bytes) &&
    isCount(value.default_share_expiry_hours) &&
    isCount(value.max_share_expiry_hours) &&
    isCount(value.max_share_downloads) &&
    isCount(value.min_password_length) &&
    isCount(value.max_password_length)
  );
}

export function isShare(value: unknown): value is Share {
  return (
    isRecord(value) &&
    isString(value.id) &&
    isString(value.file_id) &&
    isString(value.created_at) &&
    isString(value.expires_at) &&
    isCount(value.max_downloads) &&
    isCount(value.download_count) &&
    isCount(value.downloads_remaining) &&
    isNullableString(value.last_downloaded_at) &&
    isNullableString(value.revoked_at) &&
    typeof value.password_protected === "boolean" &&
    isShareStatus(value.status)
  );
}

export function isStoredFile(value: unknown): value is StoredFile {
  return (
    isRecord(value) &&
    isString(value.id) &&
    isString(value.name) &&
    isCount(value.size_bytes) &&
    isFileState(value.status) &&
    isString(value.algorithm) &&
    isString(value.created_at) &&
    isCount(value.share_count) &&
    isCount(value.active_share_count)
  );
}

export function isStoredFileDetail(value: unknown): value is StoredFileDetail {
  return isStoredFile(value) && "shares" in value && isArrayOf(isShare)(value.shares);
}

export function isFileList(value: unknown): value is FileList {
  return isRecord(value) && isArrayOf(isStoredFile)(value.items) && isCount(value.total);
}

export function isShareCreated(value: unknown): value is ShareCreated {
  return (
    isRecord(value) && isShare(value.share) && isString(value.token) && isString(value.path)
  );
}

function isActivityItem(value: unknown): value is ActivityItem {
  return (
    isRecord(value) &&
    isString(value.timestamp) &&
    isString(value.action) &&
    isString(value.result) &&
    isNullableString(value.share_id) &&
    isNullableString(value.reason)
  );
}

export function isActivityList(value: unknown): value is ActivityList {
  return isRecord(value) && isArrayOf(isActivityItem)(value.items);
}

export function isPublicShareInfo(value: unknown): value is PublicShareInfo {
  return (
    isRecord(value) &&
    value.state === "available" &&
    isNullableString(value.file_name) &&
    isCount(value.size_bytes) &&
    typeof value.password_required === "boolean" &&
    isString(value.expires_at) &&
    isCount(value.downloads_remaining)
  );
}
