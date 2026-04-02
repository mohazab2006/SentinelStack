import { NextRequest, NextResponse } from "next/server";

function stripTrailingSlash(s: string) {
  return s.replace(/\/$/, "");
}

function forwardHeaders(req: NextRequest): HeadersInit {
  const out = new Headers();
  const ct = req.headers.get("content-type");
  if (ct) out.set("content-type", ct);
  const accept = req.headers.get("accept");
  if (accept) out.set("accept", accept);
  return out;
}

/**
 * Proxies /api/{service}/... from `next dev` to nginx (default :8080). Production UI is served
 * through nginx, which handles these paths; this exists only for local dev on port 3000.
 */
export async function proxyToStack(
  req: NextRequest,
  service: "logging" | "portguard",
  pathSegments: string[]
): Promise<NextResponse> {
  if (process.env.NODE_ENV !== "development") {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const origin = stripTrailingSlash(
    process.env.SENTINELSTACK_DEV_PROXY || "http://127.0.0.1:8080"
  );
  const subpath = pathSegments.length ? pathSegments.join("/") : "";
  const targetUrl = `${origin}/api/${service}/${subpath}${req.nextUrl.search}`;

  let body: ArrayBuffer | undefined;
  if (req.method !== "GET" && req.method !== "HEAD") {
    body = await req.arrayBuffer();
  }

  let upstream: Response;
  try {
    upstream = await fetch(targetUrl, {
      method: req.method,
      headers: forwardHeaders(req),
      body: body && body.byteLength > 0 ? body : undefined,
      cache: "no-store"
    });
  } catch {
    return NextResponse.json(
      {
        error: "Upstream unreachable",
        detail: `Could not reach ${origin}. Is Docker Compose (nginx on 8080) running?`
      },
      { status: 502 }
    );
  }

  const headers = new Headers(upstream.headers);
  headers.delete("transfer-encoding");
  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers
  });
}
