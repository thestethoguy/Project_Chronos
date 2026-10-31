import { useRef, useState } from "react";
import {
  FiCheckCircle,
  FiCpu,
  FiDownload,
  FiFolderPlus,
  FiRefreshCw,
  FiUploadCloud,
  FiZap,
} from "react-icons/fi";
import { uploadTopology } from "../services/api";
import { extractErrorMessage } from "../services/topologyApi";

export type TopologyEntryMode = "standby" | "demo" | "custom";

type UploadStatus = "idle" | "scanning" | "uploading" | "success" | "error";

const SAMPLE_CUSTOM_TOPOLOGY_JSON = JSON.stringify(
  {
    devices: [
      {
        id: "wifi_gateway_01",
        name: "Branch Edge Wi-Fi Gateway",
        ip: "192.168.10.1",
        subnet: "public_dmz",
        ports: [80, 443],
        os: "OpenWrt 23.05",
        cves: ["CVE-2023-20073"],
      },
      {
        id: "vpn_concentrator",
        name: "Remote Access VPN Hub",
        ip: "192.168.10.5",
        subnet: "public_dmz",
        ports: [443, 1194],
        os: "Ubuntu 22.04 LTS",
        cves: ["CVE-2024-21762"],
      },
      {
        id: "analyst_workstation",
        name: "Operations Workstation",
        ip: "10.20.1.15",
        subnet: "internal_core",
        ports: [22, 445, 3389],
        os: "Windows 11 Enterprise",
        cves: [],
      },
      {
        id: "branch_auth_dc",
        name: "Branch Domain Controller",
        ip: "10.20.1.50",
        subnet: "internal_core",
        ports: [88, 389, 445],
        os: "Windows Server 2022",
        cves: ["CVE-2020-1472"],
      },
      {
        id: "telemetry_vault_db",
        name: "Classified Telemetry SQL Vault",
        ip: "10.20.1.100",
        subnet: "internal_core",
        ports: [5432],
        os: "Debian 12",
        cves: ["CVE-2024-10979"],
      },
    ],
    connections: [
      {
        source: "wifi_gateway_01",
        target: "analyst_workstation",
        type: "VLAN_BRIDGE",
      },
      {
        source: "vpn_concentrator",
        target: "analyst_workstation",
        type: "VPN_TUNNEL",
      },
      {
        source: "analyst_workstation",
        target: "branch_auth_dc",
        type: "SMB_AUTH",
      },
      {
        source: "branch_auth_dc",
        target: "telemetry_vault_db",
        type: "SQL_QUERY",
      },
    ],
  },
  null,
  2
);

interface TopologyUploaderProps {
  mode: TopologyEntryMode;
  activeLabel: string;
  onLaunchDemo: () => Promise<void>;
  onCustomUploaded: (
    filename: string,
    counts: { deviceCount: number; connectionCount: number }
  ) => Promise<void>;
  onUnloadTopology: () => void;
}

export function TopologyUploader({
  mode,
  activeLabel,
  onLaunchDemo,
  onCustomUploaded,
  onUnloadTopology,
}: TopologyUploaderProps) {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<UploadStatus>("idle");
  const [scanStageText, setScanStageText] = useState<string>("");
  const [demoLoading, setDemoLoading] = useState<boolean>(false);
  const [dragOver, setDragOver] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [counts, setCounts] = useState<{
    deviceCount: number;
    connectionCount: number;
  } | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  async function validateAndSetFile(selected: File | null) {
    setErrorMessage("");
    setStatus("idle");
    setCounts(null);
    if (!selected) {
      setFile(null);
      return;
    }
    if (!selected.name.toLowerCase().endsWith(".json")) {
      setErrorMessage("Please select a valid .json topology file.");
      setFile(null);
      return;
    }
    try {
      const parsed = JSON.parse(await selected.text()) as {
        devices?: unknown[];
        connections?: unknown[];
      };
      if (!Array.isArray(parsed.devices) || !Array.isArray(parsed.connections)) {
        setErrorMessage(
          "JSON file must contain 'devices' and 'connections' arrays."
        );
        setFile(null);
        return;
      }
    } catch {
      setErrorMessage("That file is not valid JSON.");
      setFile(null);
      return;
    }
    setFile(selected);
  }

  async function handleFileSelect(event: React.ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0] ?? null;
    await validateAndSetFile(selected);
  }

  async function handleDrop(event: React.DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragOver(false);
    const dropped = event.dataTransfer.files?.[0] ?? null;
    await validateAndSetFile(dropped);
  }

  async function handleSubmitCustom() {
    if (!file || status === "uploading" || status === "scanning") return;
    setErrorMessage("");
    setStatus("scanning");
    try {
      setScanStageText("Stage 1/3: Validating JSON Schema & Subnets...");
      await new Promise((r) => setTimeout(r, 220));
      setScanStageText("Stage 2/3: Mapping Multi-Hop Graph Corridors...");
      await new Promise((r) => setTimeout(r, 220));
      setScanStageText("Stage 3/3: Computing CVE Exposure & Risk Scores...");
      setStatus("uploading");

      const result = await uploadTopology(file);
      setCounts(result);
      setStatus("success");
      setScanStageText("");
      await onCustomUploaded(file.name, result);
    } catch (err) {
      setStatus("error");
      setScanStageText("");
      setErrorMessage(
        extractErrorMessage(err, "Upload failed. Please check the file format.")
      );
    }
  }

  async function handleLaunchDemoClick() {
    if (demoLoading) return;
    setErrorMessage("");
    setDemoLoading(true);
    try {
      await onLaunchDemo();
    } catch (err) {
      setErrorMessage(
        extractErrorMessage(err, "Could not load Demo Topology.")
      );
    } finally {
      setDemoLoading(false);
    }
  }

  function handleDownloadSampleTemplate() {
    const blob = new Blob([SAMPLE_CUSTOM_TOPOLOGY_JSON], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "custom_network_topology.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  return (
    <section
      className="panel uploader-panel"
      aria-label="Dual-mode topology selector and uploader"
      style={{
        border:
          mode === "standby"
            ? "1px solid rgba(56, 189, 248, 0.45)"
            : "1px solid rgba(34, 197, 94, 0.35)",
        background:
          "linear-gradient(145deg, rgba(13, 27, 48, 0.96), rgba(9, 19, 36, 0.96))",
      }}
    >
      {/* Top Header & Active Mode Banner */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
          marginBottom: 14,
        }}
      >
        <div>
          <p className="eyebrow" style={{ color: "#38bdf8", marginBottom: 4 }}>
            STEP 1 · SELECT DIGITAL TWIN BLUEPRINT MODE
          </p>
          <h2 style={{ margin: 0, fontSize: "1.15rem" }}>
            Dual-Mode Network Topology Ingestion
          </h2>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {mode === "standby" ? (
            <span
              style={{
                padding: "5px 12px",
                borderRadius: 999,
                fontSize: "0.76rem",
                fontWeight: 700,
                letterSpacing: "0.04em",
                background: "rgba(245, 158, 11, 0.14)",
                border: "1px solid rgba(245, 158, 11, 0.45)",
                color: "#fbbf24",
              }}
            >
              ⏳ STANDBY MODE — SELECT DEMO OR UPLOAD JSON
            </span>
          ) : (
            <>
              <span
                style={{
                  padding: "5px 12px",
                  borderRadius: 999,
                  fontSize: "0.76rem",
                  fontWeight: 700,
                  letterSpacing: "0.03em",
                  background:
                    mode === "demo"
                      ? "rgba(34, 197, 94, 0.15)"
                      : "rgba(56, 189, 248, 0.16)",
                  border:
                    mode === "demo"
                      ? "1px solid rgba(34, 197, 94, 0.5)"
                      : "1px solid rgba(56, 189, 248, 0.5)",
                  color: mode === "demo" ? "#4ade80" : "#38bdf8",
                }}
              >
                {mode === "demo"
                  ? `🟢 ACTIVE: [Demo Mode — ${activeLabel}]`
                  : `📂 ACTIVE: [Custom Upload — ${activeLabel}]`}
              </span>
              <button
                type="button"
                className="button"
                onClick={() => {
                  setFile(null);
                  setCounts(null);
                  setStatus("idle");
                  setErrorMessage("");
                  onUnloadTopology();
                }}
                style={{
                  padding: "6px 12px",
                  fontSize: "0.78rem",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <FiRefreshCw />
                Switch / Reset Topology
              </button>
            </>
          )}
        </div>
      </div>

      {/* Dual-Mode Cards Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
          gap: 14,
        }}
      >
        {/* MODE A: PRE-STRUCTURED 20-NODE ENTERPRISE DEMO */}
        <div
          style={{
            padding: "16px 18px",
            borderRadius: 12,
            background:
              mode === "demo"
                ? "rgba(22, 101, 52, 0.18)"
                : "rgba(15, 29, 52, 0.78)",
            border:
              mode === "demo"
                ? "1.5px solid rgba(74, 222, 128, 0.6)"
                : "1px solid rgba(77, 163, 255, 0.25)",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            gap: 12,
          }}
        >
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: 6,
              }}
            >
              <span
                style={{
                  fontSize: "0.72rem",
                  fontWeight: 700,
                  color: "#4ade80",
                  letterSpacing: "0.06em",
                }}
              >
                MODE A · INSTANT EVALUATION TEMPLATE
              </span>
              {mode === "demo" && (
                <FiCheckCircle style={{ color: "#4ade80", fontSize: "1rem" }} />
              )}
            </div>
            <h3 style={{ margin: "0 0 6px 0", fontSize: "1.02rem" }}>
              🚀 Launch 20-Node Enterprise Demo
            </h3>
            <p
              style={{
                margin: 0,
                fontSize: "0.82rem",
                color: "#94a3b8",
                lineHeight: 1.45,
              }}
            >
              Instantly loads the pre-structured 4-tier Government Core Digital
              Twin (<code>public_dmz</code> ➔ <code>internal_core</code>), 16
              historical RAG incidents, and autonomous Red vs. Blue simulation.
            </p>
          </div>

          <button
            type="button"
            className="button button-primary"
            onClick={() => void handleLaunchDemoClick()}
            disabled={demoLoading}
            style={{
              width: "100%",
              justifyContent: "center",
              padding: "10px 14px",
              fontWeight: 700,
            }}
          >
            <FiZap />
            {demoLoading
              ? "Loading 20-Node Enterprise Blueprint..."
              : mode === "demo"
              ? "Reload 20-Node Enterprise Demo"
              : "Load 20-Node Enterprise Demo"}
          </button>
        </div>

        {/* MODE B: CUSTOM USER TOPOLOGY UPLOAD (.JSON) */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => void handleDrop(e)}
          style={{
            padding: "16px 18px",
            borderRadius: 12,
            background: dragOver
              ? "rgba(56, 189, 248, 0.16)"
              : mode === "custom"
              ? "rgba(14, 116, 144, 0.22)"
              : "rgba(15, 29, 52, 0.78)",
            border: dragOver
              ? "1.5px dashed #38bdf8"
              : mode === "custom"
              ? "1.5px solid rgba(56, 189, 248, 0.65)"
              : "1px dashed rgba(148, 163, 184, 0.35)",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            gap: 10,
          }}
        >
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: 6,
                gap: 8,
              }}
            >
              <span
                style={{
                  fontSize: "0.72rem",
                  fontWeight: 700,
                  color: "#38bdf8",
                  letterSpacing: "0.06em",
                }}
              >
                MODE B · CUSTOM NETWORK BLUEPRINT (.JSON)
              </span>
              <button
                type="button"
                className="copilot-chip"
                onClick={handleDownloadSampleTemplate}
                title="Download a sample 5-node custom network_topology.json file to test upload"
                style={{
                  padding: "3px 8px",
                  fontSize: "0.71rem",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                }}
              >
                <FiDownload />
                Sample JSON Template
              </button>
            </div>

            <h3 style={{ margin: "0 0 6px 0", fontSize: "1.02rem" }}>
              <FiFolderPlus
                style={{ marginRight: 6, verticalAlign: "middle" }}
              />
              Upload Custom Topology (.json)
            </h3>
            <p
              style={{
                margin: 0,
                fontSize: "0.81rem",
                color: "#94a3b8",
                lineHeight: 1.4,
              }}
            >
              Drag &amp; drop or choose your own <code>network_topology.json</code>{" "}
              file. All Risk Scores, Critical Nodes, Attack Paths, and SOC
              Copilot answers adapt 100% dynamically to your file.
            </p>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexWrap: "wrap",
            }}
          >
            <input
              ref={fileInputRef}
              id="topology-file"
              className="uploader-file-input"
              type="file"
              accept=".json,application/json"
              onChange={(e) => void handleFileSelect(e)}
              disabled={status === "uploading" || status === "scanning"}
              style={{ flex: 1, minWidth: 180 }}
            />
            <button
              type="button"
              className="button button-primary"
              onClick={() => void handleSubmitCustom()}
              disabled={
                !file || status === "uploading" || status === "scanning"
              }
            >
              <FiUploadCloud />
              {status === "scanning" || status === "uploading"
                ? "Scanning Blueprint..."
                : "Upload & Activate"}
            </button>
          </div>
        </div>
      </div>

      {/* Feedback / 3-Stage Blueprint Scan Progress */}
      <div role="status" aria-live="polite" className="uploader-feedback">
        {scanStageText && (
          <p
            style={{
              margin: "10px 0 0 0",
              color: "#38bdf8",
              fontSize: "0.82rem",
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <FiCpu />
            {scanStageText}
          </p>
        )}
        {status === "success" && counts && mode === "custom" && (
          <p className="uploader-success" style={{ marginTop: 8 }}>
            ✓ Custom Blueprint Activated: {counts.deviceCount} devices and{" "}
            {counts.connectionCount} connections ingested into Digital Twin.
          </p>
        )}
        {errorMessage && (
          <p role="alert" className="uploader-error" style={{ marginTop: 8 }}>
            {errorMessage}
          </p>
        )}
      </div>
    </section>
  );
}
