import type { NextRequest } from "next/server";
import { proxyToStack } from "../../../lib/devStackProxy";

type Ctx = { params: { path: string[] } };

export async function GET(req: NextRequest, ctx: Ctx) {
  return proxyToStack(req, "portguard", ctx.params.path ?? []);
}

export async function POST(req: NextRequest, ctx: Ctx) {
  return proxyToStack(req, "portguard", ctx.params.path ?? []);
}

export async function PUT(req: NextRequest, ctx: Ctx) {
  return proxyToStack(req, "portguard", ctx.params.path ?? []);
}
