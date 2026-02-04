type SecretRef = {
  project: string;
  env: string;
  name: string;
};

type SecretGetResponse = {
  secretRef: SecretRef;
  value: string;
  cacheTtlSeconds?: number;
};

type Cached = { value: string; expiresAt: number };

class SecretsFetcherError extends Error {
  override name = "SecretsFetcherError";
}

class SecretsFetcherHttpError extends SecretsFetcherError {
  statusCode: number;
  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
  }
}

const cache = new Map<string, Cached>();

function normalizeKeyPart(value: string): string {
  return value.trim().toLowerCase();
}

function keyOf(ref: SecretRef): string {
  return `${normalizeKeyPart(ref.project)}:${normalizeKeyPart(ref.env)}:${normalizeKeyPart(ref.name)}`;
}

async function readTokenFromFile(filePath: string): Promise<string> {
  const fs = await import("node:fs/promises");
  return (await fs.readFile(filePath, "utf8")).trim();
}

async function getBearerTokenFromEnv(): Promise<string> {
  const direct = (process.env.SECRETS_FETCHER_TOKEN || "").trim();
  if (direct) {
    return direct;
  }

  const tokenFile =
    (process.env.SECRETS_FETCHER_TOKEN_FILE || "/var/run/secrets/kubernetes.io/serviceaccount/token")
      .trim() || "/var/run/secrets/kubernetes.io/serviceaccount/token";
  try {
    return await readTokenFromFile(tokenFile);
  } catch (err) {
    throw new SecretsFetcherError(`missing_token:${String(err)}`);
  }
}

function resolveSecretsUtilityBaseUrl(): string {
  const raw = (process.env.SECRETS_UTILITY_URL || "").trim();
  if (!raw) {
    throw new SecretsFetcherError("missing_SECRETS_UTILITY_URL");
  }
  return raw.replace(/\/$/, "");
}

async function postJson(params: {
  url: string;
  body: unknown;
  timeoutMs: number;
}): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), params.timeoutMs);
  try {
    const token = await getBearerTokenFromEnv();
    return await fetch(params.url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(params.body),
      cache: "no-store",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

function parseIntEnv(name: string, fallback: number): number {
  const raw = (process.env[name] || "").trim();
  if (!raw) {
    return fallback;
  }
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function parseFloatEnv(name: string, fallback: number): number {
  const raw = (process.env[name] || "").trim();
  if (!raw) {
    return fallback;
  }
  const n = Number.parseFloat(raw);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

async function requestSecretFromUtility(ref: SecretRef): Promise<SecretGetResponse> {
  const baseUrl = resolveSecretsUtilityBaseUrl();
  const timeoutSeconds = parseFloatEnv("SECRETS_FETCHER_TIMEOUT", 3);
  const maxRetries = parseIntEnv("SECRETS_FETCHER_RETRIES", 3);
  const url = `${baseUrl}/v1/secret:get`;
  const payload = { secretRef: ref };

  let lastError: unknown = null;
  for (let attempt = 1; attempt <= Math.max(1, maxRetries); attempt += 1) {
    try {
      const res = await postJson({ url, body: payload, timeoutMs: Math.round(timeoutSeconds * 1000) });

      if (res.status === 404) {
        throw new SecretsFetcherHttpError(404, "not_found");
      }
      if (res.status === 429 && attempt < maxRetries) {
        const retryAfter = Number.parseInt(res.headers.get("Retry-After") || "1", 10);
        const ms = Math.min(5000, Math.max(250, (Number.isFinite(retryAfter) ? retryAfter : 1) * 1000));
        await new Promise((r) => setTimeout(r, ms));
        continue;
      }
      if (res.status >= 500 && attempt < maxRetries) {
        await new Promise((r) => setTimeout(r, Math.min(1000, 50 * 2 ** attempt)));
        continue;
      }
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        throw new SecretsFetcherHttpError(res.status, `http_${res.status}:${txt}`);
      }

      const data = (await res.json()) as SecretGetResponse;
      return data;
    } catch (err) {
      lastError = err;
      const status = err instanceof SecretsFetcherHttpError ? err.statusCode : null;
      const shouldRetry = status === null || status >= 500;
      if (attempt < maxRetries && shouldRetry) {
        await new Promise((r) => setTimeout(r, Math.min(1000, 50 * 2 ** attempt)));
        continue;
      }
      break;
    }
  }
  throw new SecretsFetcherError(`request_failed:${String(lastError)}`);
}

export async function getSecret(params: {
  project: string;
  env: string;
  name: string;
}): Promise<string> {
  const ref: SecretRef = { project: params.project, env: params.env, name: params.name };
  const k = keyOf(ref);
  const now = Date.now();

  const cached = cache.get(k);
  if (cached && cached.expiresAt > now) {
    return cached.value;
  }

  const data = await requestSecretFromUtility(ref);
  const value = String(data?.value ?? "");
  const ttlSeconds = Number.isFinite(data?.cacheTtlSeconds) ? Number(data.cacheTtlSeconds) : 0;
  if (ttlSeconds > 0) {
    cache.set(k, { value, expiresAt: now + ttlSeconds * 1000 });
  }
  return value;
}

export async function getSecretOptional(params: {
  project: string;
  env: string;
  name: string;
}): Promise<string | null> {
  try {
    return await getSecret(params);
  } catch (err) {
    if (err instanceof SecretsFetcherHttpError && err.statusCode === 404) {
      return null;
    }
    throw err;
  }
}

