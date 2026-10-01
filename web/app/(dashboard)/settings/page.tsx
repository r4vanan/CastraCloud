import { api, type User } from "@/lib/api";
import { SettingsClient } from "./settings-client";

export default async function SettingsPage() {
  let user: User | null = null;
  try {
    user = await api.me();
  } catch {
    user = null;
  }

  return (
    <>
      <h1>Platform Settings</h1>
      <SettingsClient user={user} />
    </>
  );
}
