import { getSecret, getSecretOptional } from "./secrets-fetcher.js";

type BootstrapOptions = {
  env?: Record<string, string | undefined>;
};

function splitCsv(value: string | undefined): string[] {
  const raw = (value ?? "").trim();
  if (!raw) {
    return [];
  }
  return raw
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
}

function normalizeSecretNameFromEnvKey(key: string): string {
  // Convention used in other apps: env var name -> lower-case secret name.
  return key.trim().toLowerCase();
}

function requireNonEmpty(name: string, value: string | undefined): string {
  const v = (value ?? "").trim();
  if (!v) {
    throw new Error(`missing_${name}`);
  }
  return v;
}

export async function bootstrapSecretsFromSecretsUtility(opts: BootstrapOptions = {}): Promise<void> {
  const env = opts.env ?? (process.env as Record<string, string | undefined>);

  // No-op unless explicitly configured (keeps local dev and standalone installs unaffected).
  const baseUrl = (env.SECRETS_UTILITY_URL ?? "").trim();
  if (!baseUrl) {
    return;
  }

  const project = requireNonEmpty("SECRETS_PROJECT", env.SECRETS_PROJECT);
  const secretsEnv = (env.SECRETS_ENV ?? "main").trim() || "main";

  const requiredKeys = splitCsv(env.SECRETS_REQUIRED_KEYS);
  const optionalKeys = splitCsv(env.SECRETS_OPTIONAL_KEYS);

  const fetchAndSet = async (key: string, required: boolean) => {
    const k = key.trim();
    if (!k) {
      return;
    }
    if ((env[k] ?? "").trim()) {
      return;
    }
    const name = normalizeSecretNameFromEnvKey(k);
    const value = required
      ? await getSecret({ project, env: secretsEnv, name })
      : await getSecretOptional({ project, env: secretsEnv, name });
    if (value === null) {
      return;
    }
    env[k] = value;
  };

  for (const k of requiredKeys) {
    try {
      await fetchAndSet(k, true);
    } catch (err) {
      throw new Error(`failed_to_fetch_required_secret:${project}:${secretsEnv}:${k}:${String(err)}`);
    }
  }

  for (const k of optionalKeys) {
    try {
      await fetchAndSet(k, false);
    } catch (err) {
      throw new Error(`failed_to_fetch_optional_secret:${project}:${secretsEnv}:${k}:${String(err)}`);
    }
  }
}

