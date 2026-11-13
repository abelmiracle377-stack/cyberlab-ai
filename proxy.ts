import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

export async function proxy(request: NextRequest) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !key) return NextResponse.next({ request });

  let response = NextResponse.next({ request });
  const supabase = createServerClient(url, key, {
    cookies: {
      getAll: () => request.cookies.getAll(),
      setAll(cookiesToSet) {
        cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
        response = NextResponse.next({ request });
        cookiesToSet.forEach(({ name, value, options }) => response.cookies.set(name, value, options));
      },
    },
  });
  const { data: { user } } = await supabase.auth.getUser();
  const path = request.nextUrl.pathname;
  const isPublic = path === "/login" || path === "/pricing" || path.startsWith("/auth/callback") || path === "/api/paystack/webhook";
  const isBilling = path === "/billing" || path.startsWith("/api/billing/");
  const isAdmin = path === "/admin" || path.startsWith("/api/admin/");
  if (!user && !isPublic) {
    if (request.nextUrl.pathname.startsWith("/api/")) return NextResponse.json({ error: "Authentication required. Sign in to CyberLab AI." }, { status: 401 });
    const destination = request.nextUrl.clone();
    destination.pathname = "/login";
    destination.searchParams.set("next", request.nextUrl.pathname);
    return NextResponse.redirect(destination);
  }
  if (user && path === "/login") return NextResponse.redirect(new URL("/", request.url));
  if (user && !isPublic && !isBilling && !isAdmin) {
    const { data: subscription } = await supabase.from("subscriptions").select("status").eq("user_id", user.id).in("status", ["active", "comped"]).limit(1).maybeSingle();
    if (!subscription) {
      if (path.startsWith("/api/")) return NextResponse.json({ error: "An active $10/month subscription is required.", billingRequired: true }, { status: 402 });
      return NextResponse.redirect(new URL("/billing", request.url));
    }
  }
  return response;
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)"] };
