// Types for the Waka client SDK (index.js).

export interface Storage {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  delete(key: string): Promise<void>;
}
export class MemoryStorage implements Storage {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  delete(key: string): Promise<void>;
}
export class BrowserStorage implements Storage {
  constructor(name?: string);
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  delete(key: string): Promise<void>;
}

export class WakaError extends Error {
  /**
   * HTTP status. 0 when there was no usable answer: unreachable, timed out,
   * or something other than the hub or server replied.
   */
  status: number;
}

/**
 * The stream to the hub. "connecting" is the first attempt, "reconnecting"
 * every retry after it, "disconnected" when nothing listens or nobody is
 * signed in.
 */
export type ConnectionState = "disconnected" | "connecting" | "connected" | "reconnecting";

export interface Backoff {
  baseMs: number;
  factor: number;
  capMs: number;
  /** 0.2 is +/-20%. */
  jitter: number;
  /** How long a connection must last before the delays start over. */
  stableResetAfterMs: number;
}
/** 1 s, doubling, capped at 30 s, +/-20%, reset after 60 s connected. */
export const defaultBackoff: Backoff;

export interface ConnectionOptions {
  backoff?: Partial<Backoff>;
  /** From dialling to the hub's hello. Default 10 s. */
  handshakeTimeoutMs?: number;
  /** How long a checked stream has to answer. Default 10 s. */
  probeTimeoutMs?: number;
  random?: () => number;
}

/** The signed-in account's profile in the session's app. */
export interface HubUser {
  /** The app the session belongs to. */
  app: string;
  handle: string;
  name: string;
  bio: string;
  /** Shown to the account itself only. */
  email: string;
  /** Avatar URL on the hub, or "". */
  picture: string;
}

/**
 * What the hub reveals about another account: a persona, with no ID. In the
 * inbox it is the sender as they appear on the sending server.
 */
export interface PublicUser {
  handle: string;
  name: string;
  picture: string;
}

/** What the account shows one server. */
export interface ServerProfile {
  server_id: string;
  /** Each field null where the app profile applies. */
  override: { handle: string | null; name: string | null; bio: string | null; picture: string | null };
  /** What the server sees. */
  profile: PublicUser & { bio: string };
}

export interface Server {
  id: string;
  name: string;
  address: string;
  app: string;
  /** A master server: every account has it and it cannot be removed. */
  default?: boolean;
  added_at?: number;
}

export interface Resource {
  type: string;
  id: string;
}

/** A user as one server knows them. `avatar` is a path on that server. */
export interface ServerUser {
  id: string;
  issuer: string;
  subject: string;
  handle: string;
  name: string;
  bio: string;
  avatar: string;
}

export interface Grant {
  id: string;
  resource: Resource;
  kind: "user" | "link";
  user_id?: string;
  /** Role names, as the server's app declares them. A set: one or more. */
  roles: string[];
  status: "pending" | "accepted" | "declined";
  created_by?: string;
  created_at: number;
  title?: string;
  user?: ServerUser;
  invited_by?: ServerUser;
  /** In grants(): this account may change or revoke it. */
  editable?: boolean;
  link_id?: string;
  /** A link anyone can open without an account. Otherwise only accounts can join through it. */
  public?: boolean;
  label?: string;
  expires_at?: number;
  max_uses?: number;
  uses?: number;
  has_password?: boolean;
}

export interface Joinable {
  resource: Resource;
  title: string;
  roles: string[];
}

/** One of a resource's roles, as the account asking sees it. */
export interface Role {
  name: string;
  label: string;
  /** The app's permission strings this role carries. */
  perms: string[];
  /** The owner role: never handed out by share, link or role change. */
  owner?: boolean;
  /** This account may hand it out by sharing or a role change. */
  assignable: boolean;
  /** It may go on a link for accounts. */
  link: boolean;
  /** It may go on a public link. */
  public_link: boolean;
}

export interface RoleInfo {
  resource: Resource;
  roles: Role[];
  /** What this account holds: roles on the resource itself, permissions from every source. */
  mine: { roles: string[]; perms: string[] };
  /** May create links and share by handle, and see and revoke its own. */
  can_share: boolean;
  /** May change and revoke other people's grants and links. */
  can_manage: boolean;
}

/** What a link leads to, read without a session. */
export interface LinkPreview {
  server: Server;
  resource: Resource & { title: string };
  roles: { name: string; label: string }[];
  /** Who made the link, as they appear on that server. Null while locked. */
  invited_by: PublicUser | null;
  public: boolean;
  has_password: boolean;
  /** A password is set and was not given: no title and no invited_by yet. */
  locked: boolean;
  expires_at?: number;
}

export interface InboxItem {
  id: string;
  kind: "invite" | "notification";
  /** For an invite, the grant ID on the sending server. */
  ref: string;
  status: "pending" | "accepted" | "declined" | "read";
  created_at: number;
  from_server: Server | null;
  from_user: PublicUser | null;
  /** The decrypted content, or null if it was sent before this device existed. */
  body: any | null;
}

/** A server saying something changed. Best effort; never the change itself. */
export interface Hint {
  id: string;
  server: Server;
  /** What changed, as the server named it: "notebook:12". */
  key: string;
  /** Whatever the server attached, decrypted, or null. */
  body: any | null;
}

export interface Device {
  id: string;
  name: string;
  created_at: number;
  current: boolean;
}

export interface WakaClientOptions {
  hubUrl: string;
  redirectUri?: string;
  storage?: Storage;
  fetch?: typeof fetch;
  deviceName?: string;
  /** Deadline for each hub and sign-in call. Default 15 s. */
  requestTimeoutMs?: number;
  /** Timing of the hub stream. */
  connection?: ConnectionOptions;
}

export interface LoginOptions {
  prompt?: "login";
  loginHint?: string;
}

export class WakaClient {
  constructor(options: WakaClientOptions);
  hubUrl: string;

  beginLogin(options?: LoginOptions): Promise<string>;
  loginRedirect(options?: LoginOptions): Promise<void>;
  completeLogin(callbackUrl: string): Promise<HubUser | null>;
  handleRedirect(): Promise<HubUser | null>;
  isLoggedIn(): Promise<boolean>;
  logout(): Promise<void>;

  me(): Promise<HubUser>;
  updateProfile(changes: { handle?: string; name?: string; bio?: string }): Promise<HubUser>;
  setAvatar(image: Blob | ArrayBuffer | Uint8Array): Promise<HubUser>;
  removeAvatar(): Promise<void>;
  serverProfile(serverId: string): Promise<ServerProfile>;
  /** A field left out is unchanged; null goes back to the app profile. */
  updateServerProfile(serverId: string, changes: { handle?: string | null; name?: string | null; bio?: string | null }): Promise<ServerProfile>;
  clearServerProfile(serverId: string): Promise<void>;
  setServerAvatar(serverId: string, image: Blob | ArrayBuffer | Uint8Array): Promise<ServerProfile>;
  removeServerAvatar(serverId: string): Promise<void>;
  /**
   * Exact handle in this app. With `server`, resolved as that server sees
   * it, and the answer is the person's profile there.
   */
  lookupUser(handle: string, options?: { server?: string | Pick<Server, "id"> }): Promise<PublicUser>;

  devices(): Promise<Device[]>;
  removeDevice(id: string): Promise<null>;

  directory(): Promise<Server[]>;
  /** The last directory() answer, without asking the hub. */
  cachedDirectory(): Promise<Server[] | null>;
  addServer(address: string): Promise<Server>;
  removeServer(id: string): Promise<null>;
  /** For this session's app. The account that registers a server owns it. */
  registerServer(server: { name: string; address: string }): Promise<Server & { secret: string }>;
  myServers(): Promise<Server[]>;
  deleteServer(id: string): Promise<null>;
  server(server: Pick<Server, "id" | "address"> & { name?: string }): ServerConnection;

  /** What a link leads to, without signing in to its server. */
  previewLink(url: string, options?: { password?: string }): Promise<LinkPreview>;
  /**
   * Joins through a link with this account: adds the server to the
   * directory, signs in there and claims the link. Works on a server that
   * only lets in people with a grant.
   */
  joinLink(url: string, options?: { password?: string }): Promise<{ server: Server; grant: Grant }>;

  inbox(options?: { status?: string }): Promise<InboxItem[]>;
  inviteDetails(item: InboxItem): Promise<Grant | null>;
  acceptInvite(item: InboxItem): Promise<{ status: string }>;
  declineInvite(item: InboxItem): Promise<{ status: string; sender_blocked: boolean }>;
  markRead(item: InboxItem): Promise<{ status: string }>;
  deleteInboxItem(item: InboxItem): Promise<null>;
  blocks(): Promise<{ id: string; auto: boolean; created_at: number; user: PublicUser | null }[]>;
  blockSender(item: InboxItem): Promise<{ status: string; sender_blocked: boolean }>;
  unblock(blockId: string): Promise<null>;
  /**
   * Calls back with the ID of whatever lands in the inbox, and with null each
   * time the hub stream is (re)established: list the inbox again then.
   * Returns a stop function.
   */
  subscribe(onItem: (itemId: string | null) => void): () => void;
  /**
   * Calls back with each hint ("something changed on this server"). The SDK
   * does nothing else with it; syncing is the app's decision. Returns a stop
   * function.
   */
  onHint(onHint: (hint: Hint) => void | Promise<void>): () => void;

  readonly connectionState: ConnectionState;
  /** Calls back on every change. Listening keeps the stream open. */
  onConnectionState(fn: (state: ConnectionState) => void): () => void;
  /**
   * The network may have changed: check a live stream now, retry now.
   * Browsers trigger this themselves; a native shell calls it from its own
   * resume and network events.
   */
  checkConnection(online?: boolean): void;
  /** The hub ended this device's session. Not called by logout(). */
  onSessionEnded(fn: () => void): () => void;
}

export interface LinkOptions {
  /** Anyone holding it gets in without an account. Default false: for accounts only. */
  public?: boolean;
  password?: string;
  expiresAt?: number;
  maxUses?: number;
  label?: string;
}

export class ServerConnection {
  id: string;
  address: string;
  name?: string;

  /** Whether the last call got through. Null before any call. */
  readonly reachable: boolean | null;
  onReachable(fn: (reachable: boolean) => void): () => void;
  /** Asks the server whether it is there. Needs no session. */
  check(): Promise<boolean>;

  forget(): Promise<void>;
  renew(): Promise<unknown>;
  user(): Promise<ServerUser>;
  /** The current session here as a string, renewed if it ran out: for sockets. */
  session(): Promise<string>;
  fetch(path: string, init?: RequestInit): Promise<Response>;
  request<T = any>(method: string, path: string, body?: unknown): Promise<T>;

  joined(): Promise<Grant[]>;
  joinable(): Promise<Joinable[]>;
  invites(): Promise<Grant[]>;
  join(resource: Resource): Promise<Grant>;
  acceptGrant(grantId: string): Promise<null>;
  declineGrant(grantId: string): Promise<null>;
  leave(grantId: string): Promise<null>;

  roles(resource: Resource): Promise<RoleInfo>;
  grants(resource: Resource): Promise<Grant[]>;
  share(resource: Resource, target: string, roles: string | string[]): Promise<{ grant: Grant; delivered: boolean }>;
  setRoles(grantId: string, roles: string | string[]): Promise<Grant>;
  revoke(grantId: string): Promise<null>;
  createLink(resource: Resource, roles: string | string[], options?: LinkOptions): Promise<{ url: string; grant: Grant }>;
  /** With a session here already. */
  claimLink(url: string, password?: string): Promise<Grant>;
  /** With the hub login instead of a session here. WakaClient.joinLink also adds the server to the directory. */
  joinLink(url: string, options?: { password?: string }): Promise<Grant>;

  /** `owner`: this account registered the server. The owner is always an admin. */
  me(): Promise<{ user: ServerUser; admin: boolean; owner: boolean }>;
  bans(): Promise<{ user_id: string; handle: string; name: string; reason: string }[]>;
  ban(target: { userId?: string; handle?: string; reason?: string }): Promise<{ user: ServerUser }>;
  unban(userId: string): Promise<null>;
}

export function parseLink(url: string): { address: string; id: string; secret: string };

export function previewLink(url: string, options?: { password?: string; fetch?: typeof fetch; timeoutMs?: number }): Promise<LinkPreview>;

/** Public links only; a link for accounts throws 403. */
export function openLink(
  url: string,
  options?: { password?: string; fetch?: typeof fetch },
): Promise<{
  resource: Resource;
  roles: string[];
  title: string;
  fetch: (path: string, init?: RequestInit) => Promise<Response>;
}>;
