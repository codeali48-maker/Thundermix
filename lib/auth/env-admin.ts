import { createHash, timingSafeEqual } from "node:crypto";
import { getPool } from "@/lib/db/pool";

function sameText(a: string, b: string): boolean {
  return timingSafeEqual(createHash("sha256").update(a).digest(), createHash("sha256").update(b).digest());
}

/**
 * Lets ADMIN_EMAIL / ADMIN_PASSWORD (e.g. Vercel env vars) define an operator.
 * When a login matches them, the account is created or its password reset (and
 * lockout cleared) via private.upsert_admin before the normal bcrypt login runs.
 * Needs an owner DATABASE_URL; with a tp_app-only login it logs and does nothing.
 */
export async function syncEnvAdmin(email: string, password: string): Promise<void> {
  const envEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const envPassword = process.env.ADMIN_PASSWORD;
  if (!envEmail || !envPassword || envPassword.length < 10) return;
  if (!sameText(email, envEmail) || !sameText(password, envPassword)) return;

  try {
    await getPool().query("select private.upsert_admin($1, $2, $3, $4::public.admin_role)", [
      envEmail,
      envPassword,
      process.env.ADMIN_NAME ?? "Operator",
      "super_admin",
    ]);
  } catch (error) {
    console.error("[admin] env admin sync failed", (error as Error).message);
  }
}
