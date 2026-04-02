import type { NextRequest } from "next/server";
import { proxyToStack } from "../../../lib/devStackProxy";

type Ctx = { params: { path: string[] } };

export async function GET(req: NextRequest, ctx: Ctx) {
  return proxyToStack(req, "logging", ctx.params.path ?? []);
}

export async function POST(req: NextRequest, ctx: Ctx) {
  return proxyToStack(req, "logging", ctx.params.path ?? []);
}

export async function PUT(req: NextRequest, ctx: Ctx) {
  return proxyToStack(req, "logging", ctx.params.path ?? []);
}

export async function PATCH(req: NextRequest, ctx: Ctx) {
  return proxyToStack(req, "logging", ctx.params.path ?? []);
}

export async function DELETE(req: NextRequest, ctx: Ctx) {
  return proxyToStack(req, "logging", ctx.params.path ?? []);
}
