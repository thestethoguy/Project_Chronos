import { useState } from "react";
import { FiUploadCloud } from "react-icons/fi";
import { uploadTopology } from "../services/api";
import { extractErrorMessage } from "../services/topologyApi";

type UploadStatus = "idle" | "uploading" | "success" | "error";

export function TopologyUploader({
  onUploaded,
}: {
  onUploaded: () => void | Promise<void>;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<UploadStatus>("idle");
  const [errorMessage, setErrorMessage] = useState("");
  const [counts, setCounts] = useState<{
    deviceCount: number;
    connectionCount: number;
  } | null>(null);

  async function handleFileSelect(event: React.ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0] ?? null;
    setErrorMessage("");
    setStatus("idle");
    setCounts(null);
    if (!selected) {
      setFile(null);
      return;
    }
    if (!selected.name.toLowerCase().endsWith(".json")) {
      setErrorMessage("Please select a .json file.");
      setFile(null);
      return;
    }
    try {
      JSON.parse(await selected.text());
    } catch {
      setErrorMessage("That file is not valid JSON.");
      setFile(null);
      return;
    }
    setFile(selected);
  }

  async function handleSubmit() {
    if (!file || status === "uploading") return;
    setStatus("uploading");
    setErrorMessage("");
    try {
      const result = await uploadTopology(file);
      setCounts(result);
      setStatus("success");
      await onUploaded();
    } catch (err) {
      setStatus("error");
      setErrorMessage(
        extractErrorMessage(err, "Upload failed. Please check the file format.")
      );
    }
  }

  return (
    <section
      className="panel uploader-panel"
      aria-label="Topology uploader"
    >
      <div className="uploader-row">
        <div className="uploader-info">
          <p className="eyebrow">CUSTOM TOPOLOGY INGESTION</p>
          <label htmlFor="topology-file" className="control-label">
            Upload Network Topology (.json)
          </label>
        </div>

        <div className="uploader-controls">
          <input
            id="topology-file"
            className="uploader-file-input"
            type="file"
            accept=".json,application/json"
            onChange={handleFileSelect}
            disabled={status === "uploading"}
          />
          <button
            type="button"
            className="button button-primary"
            onClick={handleSubmit}
            disabled={!file || status === "uploading"}
          >
            <FiUploadCloud />
            {status === "uploading" ? "Uploading..." : "Upload topology"}
          </button>
        </div>
      </div>

      <div role="status" aria-live="polite" className="uploader-feedback">
        {status === "success" && counts && (
          <p className="uploader-success">
            Loaded {counts.deviceCount} devices and {counts.connectionCount}{" "}
            connections.
          </p>
        )}
        {errorMessage && (
          <p role="alert" className="uploader-error">
            {errorMessage}
          </p>
        )}
      </div>
    </section>
  );
}

