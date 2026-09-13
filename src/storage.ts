import {
  downloadData,
  getProperties,
  list,
  remove,
  uploadData,
} from "aws-amplify/storage";

import uploadPolicy from "../logsentinel/upload_policy.json";
import type { Analysis, PendingAnalysis } from "./types";

export const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;
export const ALLOWED_EXTENSIONS = new Set(uploadPolicy.extensions);

const idFromPath = (path: string) => path.split("/")[2] ?? "";
const analysisCache = new Map<
  string,
  { eTag?: string; analysis: Analysis }
>();
const pendingCache = new Map<string, PendingAnalysis>();

export async function loadReports(): Promise<{
  analyses: Analysis[];
  pending: PendingAnalysis[];
}> {
  const [analysisObjects, uploadObjects] = await Promise.all([
    list({
      path: ({ identityId }) => `analyses/${identityId}/`,
      options: { listAll: true },
    }),
    list({
      path: ({ identityId }) => `uploads/${identityId}/`,
      options: { listAll: true },
    }),
  ]);

  const analyses = (
    await Promise.all(
      analysisObjects.items
        .filter((item) => item.path.endsWith("/analysis.json"))
        .map(async (item) => {
          const cached = analysisCache.get(item.path);
          if (cached && item.eTag && cached.eTag === item.eTag) {
            return cached.analysis;
          }
          try {
            const downloaded = await downloadData({ path: item.path }).result;
            const analysis = JSON.parse(
              await downloaded.body.text(),
            ) as Analysis;
            analysis.storagePath = item.path;
            analysisCache.set(item.path, { eTag: item.eTag, analysis });
            return analysis;
          } catch (error) {
            console.error(`Could not load ${item.path}`, error);
            return null;
          }
        }),
    )
  ).filter((analysis): analysis is Analysis => analysis !== null);

  const completedIds = new Set(analyses.map((analysis) => analysis.id));
  const pending = (
    await Promise.all(
      uploadObjects.items.map(async (item): Promise<PendingAnalysis | null> => {
        const id = idFromPath(item.path);
        if (!id || completedIds.has(id)) return null;
        const cached = pendingCache.get(item.path);
        if (cached) return cached;
        let name = "Uploaded log";
        try {
          const properties = await getProperties({ path: item.path });
          name = properties.metadata?.["original-name"] ?? name;
        } catch {
          // The object can disappear while a refresh is in progress.
        }
        const pendingItem = {
          id,
          name,
          sourcePath: item.path,
          uploadedAt: item.lastModified,
        };
        pendingCache.set(item.path, pendingItem);
        return pendingItem;
      }),
    )
  ).filter((item): item is PendingAnalysis => item !== null);

  analyses.sort((a, b) => b.uploaded_at.localeCompare(a.uploaded_at));
  pending.sort(
    (a, b) =>
      (b.uploadedAt?.getTime() ?? 0) - (a.uploadedAt?.getTime() ?? 0),
  );
  return { analyses, pending };
}

export async function uploadLog(
  file: File,
  onProgress: (progress: number) => void,
): Promise<string> {
  const id = crypto.randomUUID();
  const extension = file.name.includes(".")
    ? `.${file.name.split(".").pop()?.toLowerCase()}`
    : "";
  const sourcePath = await uploadData({
    path: ({ identityId }) =>
      `uploads/${identityId}/${id}/original${extension}`,
    data: file,
    options: {
      contentType: file.type || "text/plain",
      metadata: { "original-name": encodeURIComponent(file.name) },
      preventOverwrite: true,
      onProgress: ({ transferredBytes, totalBytes }) => {
        if (totalBytes) onProgress(transferredBytes / totalBytes);
      },
    },
  }).result;
  return sourcePath.path;
}

export async function deleteAnalysis(analysis: Analysis): Promise<void> {
  await Promise.all(
    [analysis.meta.source_key, analysis.storagePath]
      .filter(Boolean)
      .map((path) => remove({ path })),
  );
  analysisCache.delete(analysis.storagePath);
  pendingCache.delete(analysis.meta.source_key);
}

export async function downloadReport(analysis: Analysis): Promise<void> {
  const { storagePath: _storagePath, ...report } = analysis;
  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `logsentinel-${analysis.id}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}
