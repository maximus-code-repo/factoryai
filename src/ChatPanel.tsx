import { FormEvent, KeyboardEvent, memo, useEffect, useMemo, useRef, useState } from "react";
import { generateClient } from "aws-amplify/data";
import type { Schema } from "../amplify/data/resource";
import type { Analysis } from "./types";

type ChatPanelProps = {
  analyses: Analysis[];
};

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

type ChatSession = {
  id: string;
  title: string;
  lastMessageAt: string;
};

type ChatExchange = {
  id: string;
  userContent: string;
  assistantContent: string;
  sentAt: string;
};

const client = generateClient<Schema>();
const MAX_CONTEXT_CHARS = 48_000;
const MAX_MESSAGE_CHARS = 4_000;
const PAGE_SIZE = 100;

function errorsText(errors: Array<{ message?: string }> | undefined) {
  return errors?.map((item) => item.message).filter(Boolean).join("; ") || "";
}

function flattenExchanges(exchanges: ChatExchange[]) {
  return exchanges.flatMap<ChatMessage>((exchange) => [
    { role: "user", content: exchange.userContent },
    { role: "assistant", content: exchange.assistantContent },
  ]);
}

function buildReportContext(analyses: Analysis[]) {
  const rows: string[] = [];
  let length = 2;

  for (const report of analyses) {
    const row = JSON.stringify({
      filename: report.meta.original_name,
      analyzed_at: report.meta.analyzed_at,
      format: report.meta.format,
      lines: report.parse.total_lines,
      structured_lines: report.parse.structured,
      records: report.summary.total_records,
      time_range: report.summary.time_range,
      risk_score: report.summary.risk_score,
      risk_band: report.summary.risk_band,
      severity_counts: report.summary.severity_counts,
      findings_total: report.summary.findings_total,
      flagged_ips: report.summary.flagged_ips.slice(0, 10),
      warnings: report.warnings.slice(0, 20),
    });
    const separatorLength = rows.length ? 1 : 0;
    if (length + separatorLength + row.length > MAX_CONTEXT_CHARS) {
      const notice = JSON.stringify({
        notice: `${analyses.length - rows.length} additional report summaries exceeded the context limit.`,
      });
      if (length + separatorLength + notice.length <= MAX_CONTEXT_CHARS) {
        rows.push(notice);
      }
      break;
    }
    rows.push(row);
    length += separatorLength + row.length;
  }

  return `[${rows.join(",")}]`;
}

async function listAllSessions() {
  const sessions: ChatSession[] = [];
  let nextToken: string | null | undefined;
  do {
    const result = await client.models.ChatSession.list({
      limit: PAGE_SIZE,
      nextToken,
    });
    const message = errorsText(result.errors);
    if (message) throw new Error(message);
    sessions.push(
      ...result.data.map((session) => ({
        id: session.id,
        title: session.title,
        lastMessageAt: session.lastMessageAt,
      })),
    );
    nextToken = result.nextToken;
  } while (nextToken);
  return sessions.sort((a, b) => b.lastMessageAt.localeCompare(a.lastMessageAt));
}

async function listSessionExchanges(sessionId: string) {
  const exchanges: ChatExchange[] = [];
  let nextToken: string | null | undefined;
  do {
    const result = await client.models.ChatExchange.list({
      filter: { sessionId: { eq: sessionId } },
      limit: PAGE_SIZE,
      nextToken,
    });
    const message = errorsText(result.errors);
    if (message) throw new Error(message);
    exchanges.push(
      ...result.data.map((exchange) => ({
        id: exchange.id,
        userContent: exchange.userContent,
        assistantContent: exchange.assistantContent,
        sentAt: exchange.sentAt,
      })),
    );
    nextToken = result.nextToken;
  } while (nextToken);
  return exchanges.sort((a, b) => a.sentAt.localeCompare(b.sentAt));
}

function ChatPanel({ analyses }: ChatPanelProps) {
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [exchanges, setExchanges] = useState<ChatExchange[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [collapsed, setCollapsed] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const messages = useMemo(() => flattenExchanges(exchanges), [exchanges]);
  const reportContext = useMemo(() => buildReportContext(analyses), [analyses]);

  useEffect(() => {
    let active = true;
    void listAllSessions()
      .then((loaded) => {
        if (!active) return;
        setSessions(loaded);
        setSelectedId(loaded[0]?.id ?? null);
        if (!loaded.length) setLoadingHistory(false);
      })
      .catch((loadError) => {
        if (!active) return;
        setError(loadError instanceof Error ? loadError.message : "Could not load chats.");
        setLoadingHistory(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    if (!selectedId) {
      setExchanges([]);
      setLoadingHistory(false);
      return () => {
        active = false;
      };
    }

    setLoadingHistory(true);
    setError("");
    void listSessionExchanges(selectedId)
      .then((loaded) => {
        if (active) setExchanges(loaded);
      })
      .catch((loadError) => {
        if (active) {
          setError(loadError instanceof Error ? loadError.message : "Could not load this chat.");
        }
      })
      .finally(() => {
        if (active) setLoadingHistory(false);
      });
    return () => {
      active = false;
    };
  }, [selectedId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [messages, busy]);

  function newChat() {
    if (busy) return;
    setSelectedId(null);
    setExchanges([]);
    setInput("");
    setError("");
    setStatus("");
  }

  async function saveExchange(
    sessionId: string | null,
    title: string,
    exchange: Omit<ChatExchange, "id">,
  ) {
    let activeSession = sessions.find((session) => session.id === sessionId);
    if (!activeSession) {
      const created = await client.models.ChatSession.create({
        title,
        lastMessageAt: exchange.sentAt,
      });
      const message = errorsText(created.errors);
      if (message || !created.data) throw new Error(message || "Could not create the chat.");
      activeSession = {
        id: created.data.id,
        title: created.data.title,
        lastMessageAt: created.data.lastMessageAt,
      };
    }

    const saved = await client.models.ChatExchange.create({
      sessionId: activeSession.id,
      userContent: exchange.userContent,
      assistantContent: exchange.assistantContent,
      sentAt: exchange.sentAt,
    });
    const saveMessage = errorsText(saved.errors);
    if (saveMessage || !saved.data) throw new Error(saveMessage || "Could not save the answer.");

    const updated = await client.models.ChatSession.update({
      id: activeSession.id,
      lastMessageAt: exchange.sentAt,
    });
    const updateMessage = errorsText(updated.errors);
    if (updateMessage) throw new Error(updateMessage);

    const savedExchange: ChatExchange = {
      id: saved.data.id,
      userContent: saved.data.userContent,
      assistantContent: saved.data.assistantContent,
      sentAt: saved.data.sentAt,
    };
    const savedSession = { ...activeSession, lastMessageAt: exchange.sentAt };
    setSessions((current) =>
      [savedSession, ...current.filter((item) => item.id !== savedSession.id)].sort(
        (a, b) => b.lastMessageAt.localeCompare(a.lastMessageAt),
      ),
    );
    setSelectedId(savedSession.id);
    setExchanges((current) => [...current, savedExchange]);
  }

  async function sendMessage(event: FormEvent) {
    event.preventDefault();
    const message = input.trim();
    if (!message || busy || loadingHistory) return;
    if (message.length > MAX_MESSAGE_CHARS) {
      setError(`Messages are limited to ${MAX_MESSAGE_CHARS.toLocaleString()} characters.`);
      return;
    }

    const sourceSessionId = selectedId;
    const sourceExchanges = exchanges;
    setBusy(true);
    setError("");
    setStatus("Nova 2 Lite is preparing an answer.");
    setInput("");

    try {
      const response = await client.mutations.chat({
        message,
        historyJson: JSON.stringify(flattenExchanges(sourceExchanges).slice(-12)),
        reportContextJson: reportContext,
      });
      const responseError = errorsText(response.errors);
      if (responseError || !response.data?.answer) {
        throw new Error(responseError || "Nova 2 Lite returned no answer.");
      }

      const exchange = {
        userContent: message,
        assistantContent: response.data.answer,
        sentAt: new Date().toISOString(),
      };
      setExchanges((current) => [...current, { id: `pending-${exchange.sentAt}`, ...exchange }]);
      setStatus(`Answered by ${response.data.modelId}. Saving this chat.`);

      try {
        await saveExchange(
          sourceSessionId,
          message.slice(0, 60) || "New chat",
          exchange,
        );
        setExchanges((current) =>
          current.filter((item) => item.id !== `pending-${exchange.sentAt}`),
        );
        setStatus(`Answered by ${response.data.modelId} and saved privately.`);
      } catch (saveError) {
        setError(
          `The answer was received but could not be saved. ${
            saveError instanceof Error ? saveError.message : ""
          }`.trim(),
        );
        setStatus(`Answered by ${response.data.modelId}.`);
      }
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Chat request failed.");
      setInput(message);
      setStatus("");
    } finally {
      setBusy(false);
    }
  }

  async function selectSession(id: string) {
    if (busy) return;
    setSelectedId(id || null);
    setInput("");
    setStatus("");
  }

  async function deleteSession() {
    if (!selectedId || busy) return;
    setBusy(true);
    setError("");
    try {
      const stored = await listSessionExchanges(selectedId);
      for (const exchange of stored) {
        const deleted = await client.models.ChatExchange.delete({ id: exchange.id });
        const message = errorsText(deleted.errors);
        if (message) throw new Error(message);
      }
      const deletedSession = await client.models.ChatSession.delete({ id: selectedId });
      const message = errorsText(deletedSession.errors);
      if (message) throw new Error(message);
      const remaining = sessions.filter((session) => session.id !== selectedId);
      setSessions(remaining);
      setSelectedId(remaining[0]?.id ?? null);
      setExchanges([]);
      setStatus("");
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : "Could not delete the chat.");
    } finally {
      setBusy(false);
    }
  }

  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      event.currentTarget.form?.requestSubmit();
    }
  }

  return (
    <aside className={`chat-panel ${collapsed ? "is-collapsed" : ""}`} aria-label="Nova 2 Lite chat">
      <div className="chat-panel-header">
        <div>
          <p className="chat-kicker">Amazon Bedrock</p>
          <h2>Ask Nova 2 Lite</h2>
        </div>
        <div className="chat-header-actions">
          <button type="button" className="btn small" onClick={newChat} disabled={busy}>
            New
          </button>
          <button
            type="button"
            className="btn small chat-collapse"
            onClick={() => setCollapsed((current) => !current)}
            aria-expanded={!collapsed}
          >
            {collapsed ? "Open" : "Close"}
          </button>
        </div>
      </div>

      <div className="chat-panel-body">
        <div className="chat-history-tools">
          <label htmlFor="chat-session">Saved chat</label>
          <div className="chat-session-row">
            <select
              id="chat-session"
              value={selectedId ?? ""}
              onChange={(event) => void selectSession(event.target.value)}
              disabled={busy || loadingHistory}
            >
              <option value="">New chat</option>
              {sessions.map((session) => (
                <option key={session.id} value={session.id}>
                  {session.title}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="btn danger small"
              onClick={() => void deleteSession()}
              disabled={!selectedId || busy || loadingHistory}
            >
              Delete
            </button>
          </div>
        </div>

        <div className="chat-messages" role="log" aria-label="Chat messages">
          {loadingHistory ? (
            <p className="chat-empty">Loading your saved chat…</p>
          ) : messages.length === 0 ? (
            <p className="chat-empty">
              Ask a general question or ask about all report summaries currently loaded.
            </p>
          ) : (
            messages.map((item, index) => (
              <article className={`chat-message ${item.role}`} key={`${item.role}-${index}`}>
                <strong>{item.role === "user" ? "You" : "Nova"}</strong>
                <p>{item.content}</p>
              </article>
            ))
          )}
          {busy ? <p className="chat-thinking">Nova is thinking…</p> : null}
          <div ref={messagesEndRef} />
        </div>

        <form className="chat-form" onSubmit={(event) => void sendMessage(event)}>
          <label className="sr-only" htmlFor="chat-input">
            Message Nova 2 Lite
          </label>
          <textarea
            id="chat-input"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={handleKeyDown}
            maxLength={MAX_MESSAGE_CHARS}
            placeholder="Ask about your reports or anything else…"
            rows={3}
            disabled={busy || loadingHistory}
          />
          <div className="chat-form-footer">
            <span>{analyses.length} report summaries in context</span>
            <button className="btn primary" type="submit" disabled={busy || loadingHistory || !input.trim()}>
              {busy ? "Sending…" : "Send"}
            </button>
          </div>
        </form>

        {error ? <p className="error-text chat-error" role="alert">{error}</p> : null}
        <p className="chat-status" aria-live="polite">{status}</p>
        <p className="chat-disclaimer">AI can make mistakes. Verify important answers.</p>
      </div>
    </aside>
  );
}

export default memo(ChatPanel);
