import { NextRequest } from "next/server";

export const runtime = "nodejs";
export const maxDuration = 60;

const allowedAudio = new Set(["audio/mpeg", "audio/mp3", "audio/wav", "audio/x-wav", "audio/flac", "audio/x-flac", "audio/mp4", "audio/x-m4a", "audio/ogg", "audio/webm", "audio/aac", "audio/mp4a-latm"]);

export async function POST(request: NextRequest) {
  try {
    if (!process.env.OPENROUTER_API_KEY) {
      return Response.json({ error: "Audio transcription is unavailable: OPENROUTER_API_KEY is not configured." }, { status: 503 });
    }
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return Response.json({ error: "Choose an audio file to transcribe." }, { status: 400 });
    if (file.size < 1 || file.size > 4 * 1024 * 1024) return Response.json({ error: "Audio must be between 1 byte and 4 MB." }, { status: 413 });
    if (!allowedAudio.has(file.type.split(";")[0])) return Response.json({ error: "Unsupported audio format. Use MP3, WAV, FLAC, M4A, OGG, WebM or AAC." }, { status: 415 });
    const upstream = new FormData();
    upstream.append("file", file, file.name || "recording.webm");
    upstream.append("model", "openai/whisper-1");
    const response = await fetch("https://openrouter.ai/api/v1/audio/transcriptions", {
      method: "POST",
      headers: { Authorization: "Bearer " + process.env.OPENROUTER_API_KEY },
      body: upstream,
      signal: AbortSignal.timeout(55000),
      cache: "no-store",
    });
    const result = await response.json();
    if (!response.ok) return Response.json({ error: result.error?.message || "Transcription provider returned HTTP " + response.status + "." }, { status: response.status });
    if (typeof result.text !== "string" || !result.text.trim()) return Response.json({ error: "The transcription provider returned no transcript." }, { status: 502 });
    return Response.json({ text: result.text, usage: result.usage || null, model: "openai/whisper-1" });
  } catch (error) {
    console.error("CyberLab audio transcription failed:", error);
    return Response.json({ error: "Audio transcription failed. Check the file format and provider configuration, then try again." }, { status: 500 });
  }
}
