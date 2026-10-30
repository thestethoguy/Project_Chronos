import type { AxiosError } from "axios";
import type { NetworkTopologyFile } from "../types/simulation";
import {
  fetchTopology as apiFetchTopology,
  uploadTopology as apiUploadTopology,
  useMockData,
} from "./api";

export const isMockMode = useMockData;

/** Turns FastAPI error payloads (string or pydantic list) into one readable message. */
export function extractErrorMessage(err: unknown, fallback: string): string {
  const e = err as AxiosError<{ detail?: unknown }> & { message?: string };
  const detail = e?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d: unknown) => {
        const item = d as { msg?: string; loc?: Array<string | number> } | null;
        return item?.msg
          ? `${(item.loc ?? []).join(".")}: ${item.msg}`
          : String(d);
      })
      .slice(0, 5)
      .join("; ");
  }
  return e?.message || fallback;
}

export async function uploadTopology(
  file: File
): Promise<{ deviceCount: number; connectionCount: number }> {
  return apiUploadTopology(file);
}

export async function fetchTopology(): Promise<NetworkTopologyFile> {
  return apiFetchTopology();
}

