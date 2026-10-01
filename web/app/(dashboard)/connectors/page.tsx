import { api, type CloudConnector } from "@/lib/api";
import { ConnectorsClient } from "./connectors-client";

export default async function ConnectorsPage() {
  let connectors: CloudConnector[] = [];
  try {
    connectors = await api.connectors();
  } catch {
    connectors = [];
  }

  return (
    <>
      <h1>Cloud Integrations & Posture Scans</h1>
      <ConnectorsClient initialConnectors={connectors} />
    </>
  );
}
