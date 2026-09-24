const ALLOWED_ORIGINS = [
  "http://localhost:5173",
  "https://personal-portfolio.workwithsasan.workers.dev",
];

const getCorsHeaders = (request) => {
  const origin = request.headers.get("Origin");

  const headers = {
    "Access-Control-Allow-Methods":
      "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true",
  };

  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
};

const jsonResponse = (
  request,
  data,
  status = 200,
  extraHeaders = {}
) => {
  return Response.json(data, {
    status,
    headers: {
      ...getCorsHeaders(request),
      ...extraHeaders,
    },
  });
};

// --------------------------------
// Generate random session token
// --------------------------------
const generateToken = () => {
  const bytes = new Uint8Array(32);

  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map((byte) =>
      byte.toString(16).padStart(2, "0")
    )
    .join("");
};

// --------------------------------
// SHA-256 token hash
// --------------------------------
const hashToken = async (token) => {
  const data = new TextEncoder().encode(token);

  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return Array.from(new Uint8Array(hashBuffer))
    .map((byte) =>
      byte.toString(16).padStart(2, "0")
    )
    .join("");
};

// --------------------------------
// Parse cookies
// --------------------------------
const parseCookies = (cookieHeader) => {
  if (!cookieHeader) {
    return {};
  }

  return cookieHeader
    .split(";")
    .reduce((cookies, cookie) => {
      const [key, ...value] = cookie
        .trim()
        .split("=");

      cookies[key] = value.join("=");

      return cookies;
    }, {});
};

// --------------------------------
// Get authenticated session
// --------------------------------
const getSession = async (request, env) => {
  const cookieHeader =
    request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies = parseCookies(cookieHeader);
  const token = cookies.admin_session;

  if (!token) {
    return null;
  }

  const tokenHash = await hashToken(token);

  const session = await env.portfolio_messages
    .prepare(`
      SELECT id, expires_at
      FROM admin_sessions
      WHERE token_hash = ?
      LIMIT 1
    `)
    .bind(tokenHash)
    .first();

  if (!session) {
    return null;
  }

  // Check expiration
  if (
    new Date(session.expires_at) <=
    new Date()
  ) {
    await env.portfolio_messages
      .prepare(`
        DELETE FROM admin_sessions
        WHERE id = ?
      `)
      .bind(session.id)
      .run();

    return null;
  }

  return session;
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // --------------------------------
    // CORS Preflight
    // --------------------------------
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(request),
      });
    }

    // --------------------------------
    // POST /api/messages
    // --------------------------------
    if (
      request.method === "POST" &&
      url.pathname === "/api/messages"
    ) {
      try {
        const body = await request.json();

        const name = body.name?.trim();
        const email = body.email?.trim();
        const subject =
          body.subject?.trim() || "";
        const message = body.message?.trim();

        if (!name || !email || !message) {
          return jsonResponse(
            request,
            {
              success: false,
              message:
                "Name, email and message are required.",
            },
            400
          );
        }

        const result =
          await env.portfolio_messages
            .prepare(`
              INSERT INTO messages
              (name, email, subject, message)
              VALUES (?, ?, ?, ?)
            `)
            .bind(
              name,
              email,
              subject,
              message
            )
            .run();

        return jsonResponse(
          request,
          {
            success: true,
            message:
              "Your message has been sent successfully.",
            id: result.meta.last_row_id,
          },
          201
        );
      } catch (error) {
        console.error(error);

        return jsonResponse(
          request,
          {
            success: false,
            message: "Something went wrong.",
          },
          500
        );
      }
    }

    // --------------------------------
    // POST /api/admin/login
    // --------------------------------
    if (
      request.method === "POST" &&
      url.pathname === "/api/admin/login"
    ) {
      try {
        const body = await request.json();

        const username =
          body.username?.trim();
        const password = body.password;

        if (!username || !password) {
          return jsonResponse(
            request,
            {
              success: false,
              message:
                "Username and password are required.",
            },
            400
          );
        }

        // Check credentials
        if (
          username !== env.ADMIN_USERNAME ||
          password !== env.ADMIN_PASSWORD
        ) {
          return jsonResponse(
            request,
            {
              success: false,
              message:
                "Invalid username or password.",
            },
            401
          );
        }

        // Generate session token
        const token = generateToken();

        // Hash token
        const tokenHash =
          await hashToken(token);

        // Session expires in 24 hours
        const expiresAt = new Date(
          Date.now() +
            24 * 60 * 60 * 1000
        ).toISOString();

        // Save session
        await env.portfolio_messages
          .prepare(`
            INSERT INTO admin_sessions
            (token_hash, expires_at)
            VALUES (?, ?)
          `)
          .bind(
            tokenHash,
            expiresAt
          )
          .run();

        // Set HttpOnly cookie
        const cookie = [
          `admin_session=${token}`,
          "HttpOnly",
          "Secure",
          "SameSite=Lax",
          "Path=/",
          "Max-Age=86400",
        ].join("; ");

        return jsonResponse(
          request,
          {
            success: true,
            message: "Login successful.",
          },
          200,
          {
            "Set-Cookie": cookie,
          }
        );
      } catch (error) {
        console.error(error);

        return jsonResponse(
          request,
          {
            success: false,
            message: "Something went wrong.",
          },
          500
        );
      }
    }

    // --------------------------------
    // GET /api/admin/me
    // --------------------------------
    if (
      request.method === "GET" &&
      url.pathname === "/api/admin/me"
    ) {
      try {
        const session =
          await getSession(request, env);

        if (!session) {
          return jsonResponse(
            request,
            {
              success: false,
              authenticated: false,
            },
            401
          );
        }

        return jsonResponse(request, {
          success: true,
          authenticated: true,
        });
      } catch (error) {
        console.error(error);

        return jsonResponse(
          request,
          {
            success: false,
            authenticated: false,
          },
          500
        );
      }
    }

    // --------------------------------
    // GET /api/admin/messages
    // --------------------------------
    if (
      request.method === "GET" &&
      url.pathname === "/api/admin/messages"
    ) {
      try {
        const session =
          await getSession(request, env);

        if (!session) {
          return jsonResponse(
            request,
            {
              success: false,
              message: "Unauthorized.",
            },
            401
          );
        }

        const result =
          await env.portfolio_messages
            .prepare(`
              SELECT
                id,
                name,
                email,
                subject,
                message,
                created_at,
                is_read
              FROM messages
              ORDER BY created_at DESC
            `)
            .all();

        return jsonResponse(request, {
          success: true,
          messages: result.results,
        });
      } catch (error) {
        console.error(error);

        return jsonResponse(
          request,
          {
            success: false,
            message: "Something went wrong.",
          },
          500
        );
      }
    }

    // --------------------------------
    // PATCH /api/admin/messages/:id/read
    // --------------------------------
    if (
      request.method === "PATCH" &&
      url.pathname.match(
        /^\/api\/admin\/messages\/\d+\/read$/
      )
    ) {
      try {
        const session =
          await getSession(request, env);

        if (!session) {
          return jsonResponse(
            request,
            {
              success: false,
              message: "Unauthorized.",
            },
            401
          );
        }

        const messageId = Number(
          url.pathname.split("/")[4]
        );

        if (!Number.isInteger(messageId)) {
          return jsonResponse(
            request,
            {
              success: false,
              message: "Invalid message ID.",
            },
            400
          );
        }

        const result =
          await env.portfolio_messages
            .prepare(`
              UPDATE messages
              SET is_read = 1
              WHERE id = ?
            `)
            .bind(messageId)
            .run();

        if (result.meta.changes === 0) {
          return jsonResponse(
            request,
            {
              success: false,
              message: "Message not found.",
            },
            404
          );
        }

        return jsonResponse(request, {
          success: true,
          message:
            "Message marked as read.",
        });
      } catch (error) {
        console.error(error);

        return jsonResponse(
          request,
          {
            success: false,
            message: "Something went wrong.",
          },
          500
        );
      }
    }

    // --------------------------------
    // DELETE /api/admin/messages/:id
    // --------------------------------
    if (
      request.method === "DELETE" &&
      url.pathname.match(
        /^\/api\/admin\/messages\/\d+$/
      )
    ) {
      try {
        const session =
          await getSession(request, env);

        if (!session) {
          return jsonResponse(
            request,
            {
              success: false,
              message: "Unauthorized.",
            },
            401
          );
        }

        const messageId = Number(
          url.pathname.split("/")[4]
        );

        if (!Number.isInteger(messageId)) {
          return jsonResponse(
            request,
            {
              success: false,
              message: "Invalid message ID.",
            },
            400
          );
        }

        const result =
          await env.portfolio_messages
            .prepare(`
              DELETE FROM messages
              WHERE id = ?
            `)
            .bind(messageId)
            .run();

        if (result.meta.changes === 0) {
          return jsonResponse(
            request,
            {
              success: false,
              message: "Message not found.",
            },
            404
          );
        }

        return jsonResponse(request, {
          success: true,
          message:
            "Message deleted successfully.",
        });
      } catch (error) {
        console.error(error);

        return jsonResponse(
          request,
          {
            success: false,
            message: "Something went wrong.",
          },
          500
        );
      }
    }

    // --------------------------------
    // POST /api/admin/logout
    // --------------------------------
    if (
      request.method === "POST" &&
      url.pathname === "/api/admin/logout"
    ) {
      try {
        const cookieHeader =
          request.headers.get("Cookie");

        if (cookieHeader) {
          const cookies =
            parseCookies(cookieHeader);

          const token =
            cookies.admin_session;

          if (token) {
            const tokenHash =
              await hashToken(token);

            await env.portfolio_messages
              .prepare(`
                DELETE FROM admin_sessions
                WHERE token_hash = ?
              `)
              .bind(tokenHash)
              .run();
          }
        }

        const cookie = [
          "admin_session=",
          "HttpOnly",
          "Secure",
          "SameSite=Lax",
          "Path=/",
          "Max-Age=0",
        ].join("; ");

        return jsonResponse(
          request,
          {
            success: true,
            message:
              "Logout successful.",
          },
          200,
          {
            "Set-Cookie": cookie,
          }
        );
      } catch (error) {
        console.error(error);

        return jsonResponse(
          request,
          {
            success: false,
            message: "Something went wrong.",
          },
          500
        );
      }
    }

    // --------------------------------
    // Default
    // --------------------------------
    return jsonResponse(request, {
      success: true,
      message: "Portfolio API is running.",
    });
  },
};
