"use client";

import { useState } from "react";
import { type User } from "@/lib/api";
import { AccountSecurity } from "./account-security";
import { UsersPanel } from "./users-client";

export function SettingsClient({ user }: { user: User | null }) {
  const [tab, setTab] = useState<"account" | "users">("account");
  const isOwner = user?.role === "owner";

  return (
    <>
      <div className="filters">
        <button className={`btn ${tab === "account" ? "active" : ""}`} onClick={() => setTab("account")}>
          Account Security
        </button>
        {isOwner && (
          <button className={`btn ${tab === "users" ? "active" : ""}`} onClick={() => setTab("users")}>
            Users
          </button>
        )}
      </div>

      {tab === "account" && <AccountSecurity initialUser={user} />}
      {tab === "users" && isOwner && <UsersPanel currentUserId={user?.id} />}
    </>
  );
}
