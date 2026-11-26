/** Shapes returned by the encrypted-file API. Keep in sync with backend/app/schemas/files.py. */

export const SHARE_STATUSES = ["active", "expired", "revoked", "exhausted"] as const;
export type ShareStatus = (typeof SHARE_STATUSES)[number];

export const FILE_STATES = ["active", "corrupt"] as const;
export type FileState = (typeof FILE_STATES)[number];

export interface FileFeatureStatus {
  configured: boolean;
  max_file_size_bytes: number;
  default_share_expiry_hours: number;
  max_share_expiry_hours: number;
  max_share_downloads: number;
  min_password_length: number;
  max_password_length: number;
}

export interface Share {
  id: string;
  file_id: string;
  created_at: string;
  expires_at: string;
  max_downloads: number;
  download_count: number;
  downloads_remaining: number;
  last_downloaded_at: string | null;
  revoked_at: string | null;
  password_protected: boolean;
  status: ShareStatus;
}

export interface StoredFile {
  id: string;
  name: string;
  size_bytes: number;
  status: FileState;
  algorithm: string;
  created_at: string;
  share_count: number;
  active_share_count: number;
}

export interface StoredFileDetail extends StoredFile {
  shares: Share[];
}

export interface FileList {
  items: StoredFile[];
  total: number;
}

export interface ShareRequest {
  expires_in_hours?: number;
  max_downloads?: number;
  password?: string;
}

export interface ShareCreated {
  share: Share;
  /** Shown exactly once: only its SHA-256 is stored, so it cannot be shown again. */
  token: string;
  /** The page a recipient opens, for example `/share/<token>`. */
  path: string;
}

export interface ActivityItem {
  timestamp: string;
  action: string;
  result: string;
  share_id: string | null;
  reason: string | null;
}

export interface ActivityList {
  items: ActivityItem[];
}

/** What a link offers, from `GET /api/v1/shares/<token>`. */
export interface PublicShareInfo {
  state: "available";
  /** Null while a password is still required: the name is revealed only to someone who has it. */
  file_name: string | null;
  size_bytes: number;
  password_required: boolean;
  expires_at: string;
  downloads_remaining: number;
}
