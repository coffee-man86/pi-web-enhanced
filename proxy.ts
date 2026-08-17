import { NextResponse, type NextRequest } from "next/server";
import {
  isApiRequestAllowed,
  isApiRequestHostAllowed,
} from "@/lib/request-security";
import {
  isValidBasicAuthorization,
  isWebPasswordEnabled,
} from "@/lib/web-auth";

export function proxy(request: NextRequest) {
  const isApiRequest = request.nextUrl.pathname === "/api"
    || request.nextUrl.pathname.startsWith("/api/");
  const isTrustedRequest = isApiRequest
    ? isApiRequestAllowed(request)
    : isApiRequestHostAllowed(request);

  if (!isTrustedRequest) {
    if (!isApiRequest) {
      return new NextResponse("Untrusted request", { status: 403 });
    }
    return NextResponse.json({ error: "Untrusted API request" }, { status: 403 });
  }

  const password = process.env.PI_WEB_PASSWORD;
  if (isWebPasswordEnabled(password)) {
    const authorization = request.headers.get("authorization");
    const authorized = isValidBasicAuthorization(authorization, password);
    // 登录日志（供白名单）：记录结果、用户名、客户端 IP
    if (authorization) {
      // 仅在请求携带与 PI_WEB_TRUST_PROXY_TOKEN 匹配的密钥头时才信任
      // X-Forwarded-For（由可信反代 2FA 代理写入）。否则直接访问时客户端可
      // 伪造该头污染白名单日志，一律记 unknown。
      const trustToken = process.env.PI_WEB_TRUST_PROXY_TOKEN;
      const presented = request.headers.get("x-piweb-proxy-token");
      const trustProxy = Boolean(trustToken && presented && presented === trustToken);
      const ip = trustProxy
        ? (request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
          || request.headers.get("x-real-ip")
          || "unknown")
        : "unknown";
      let username = "-";
      const match = /^Basic\s+(\S+)$/i.exec(authorization);
      if (match) {
        try {
          username = Buffer.from(match[1], "base64").toString("utf-8").split(":")[0];
        } catch {
          // ignore malformed credentials
        }
      }
      console.log(`[piweb-auth] ${authorized ? "OK" : "FAIL"} user=${username} ip=${ip}`);
    }
    if (!authorized) {
      return new NextResponse("Authentication required", {
        status: 401,
        headers: {
          "Cache-Control": "no-store",
          "WWW-Authenticate": 'Basic realm="Pi Web"',
        },
      });
    }
  }

  return NextResponse.next();
}

export const config = { matcher: ["/", "/api/:path*"] };
