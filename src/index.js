const BOOKING_TIMES = [
	'09:00',
	'09:30',
	'10:00',
	'10:30',
	'11:00',
	'11:30',
	'12:00',
	'12:30',
	'13:00',
	'13:30',
	'14:00',
	'14:30',
	'15:00',
	'15:30',
	'16:00',
	'16:30',
	'17:00',
];

const ALLOWED_ORIGINS = ['http://localhost:3000', 'http://localhost:5173', 'https://personal-portfolio.workwithsasan.workers.dev'];

const getCorsHeaders = (request) => {
	const origin = request.headers.get('Origin');

	const headers = {
		'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type',
		'Access-Control-Allow-Credentials': 'true',
	};

	if (origin && ALLOWED_ORIGINS.includes(origin)) {
		headers['Access-Control-Allow-Origin'] = origin;
	}

	return headers;
};

const jsonResponse = (request, data, status = 200, extraHeaders = {}) => {
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
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join('');
};

// --------------------------------
// SHA-256 token hash
// --------------------------------
const hashToken = async (token) => {
	const data = new TextEncoder().encode(token);

	const hashBuffer = await crypto.subtle.digest('SHA-256', data);

	return Array.from(new Uint8Array(hashBuffer))
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join('');
};

// --------------------------------
// Parse cookies
// --------------------------------
const parseCookies = (cookieHeader) => {
	if (!cookieHeader) {
		return {};
	}

	return cookieHeader.split(';').reduce((cookies, cookie) => {
		const [key, ...value] = cookie.trim().split('=');

		cookies[key] = value.join('=');

		return cookies;
	}, {});
};

// --------------------------------
// Get authenticated session
// --------------------------------
const getSession = async (request, env) => {
	const cookieHeader = request.headers.get('Cookie');

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
		.prepare(
			`
      SELECT id, expires_at
      FROM admin_sessions
      WHERE token_hash = ?
      LIMIT 1
    `,
		)
		.bind(tokenHash)
		.first();

	if (!session) {
		return null;
	}

	// Check expiration
	if (new Date(session.expires_at) <= new Date()) {
		await env.portfolio_messages
			.prepare(
				`
        DELETE FROM admin_sessions
        WHERE id = ?
      `,
			)
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
		if (request.method === 'OPTIONS') {
			return new Response(null, {
				status: 204,
				headers: getCorsHeaders(request),
			});
		}

		// --------------------------------
		// POST /api/messages
		// --------------------------------
		if (request.method === 'POST' && url.pathname === '/api/messages') {
			try {
				const body = await request.json();

				const name = body.name?.trim();
				const email = body.email?.trim();
				const subject = body.subject?.trim() || '';
				const message = body.message?.trim();

				if (!name || !email || !message) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Name, email and message are required.',
						},
						400,
					);
				}

				const result = await env.portfolio_messages
					.prepare(
						`
              INSERT INTO messages
              (name, email, subject, message)
              VALUES (?, ?, ?, ?)
            `,
					)
					.bind(name, email, subject, message)
					.run();

				return jsonResponse(
					request,
					{
						success: true,
						message: 'Your message has been sent successfully.',
						id: result.meta.last_row_id,
					},
					201,
				);
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}

		// --------------------------------
		// POST /api/admin/login
		// --------------------------------
		if (request.method === 'POST' && url.pathname === '/api/admin/login') {
			try {
				const body = await request.json();

				const username = body.username?.trim();
				const password = body.password;

				if (!username || !password) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Username and password are required.',
						},
						400,
					);
				}

				// Check credentials
				if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid username or password.',
						},
						401,
					);
				}

				// Generate session token
				const token = generateToken();

				// Hash token
				const tokenHash = await hashToken(token);

				// Session expires in 24 hours
				const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

				// Save session
				await env.portfolio_messages
					.prepare(
						`
            INSERT INTO admin_sessions
            (token_hash, expires_at)
            VALUES (?, ?)
          `,
					)
					.bind(tokenHash, expiresAt)
					.run();

				// Set HttpOnly cookie
				const cookie = [`admin_session=${token}`, 'HttpOnly', 'Secure', 'SameSite=None', 'Path=/', 'Max-Age=86400'].join('; ');

				return jsonResponse(
					request,
					{
						success: true,
						message: 'Login successful.',
					},
					200,
					{
						'Set-Cookie': cookie,
					},
				);
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}

		// --------------------------------
		// POST /api/meetings
		// --------------------------------
		if (request.method === 'POST' && url.pathname === '/api/meetings') {
			try {
				const body = await request.json();

				const meetingDate = body.meetingDate?.trim();
				const meetingTime = body.meetingTime?.trim();

				const name = body.name?.trim();
				const email = body.email?.trim();

				const topic = body.topic?.trim() || '';
				const notes = body.notes?.trim() || '';
				const timezone = body.timezone?.trim() || '';

				// ------------------------------
				// Required fields
				// ------------------------------
				if (!meetingDate || !meetingTime || !name || !email) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Date, time, name and email are required.',
						},
						400,
					);
				}

				// ------------------------------
				// Validate date format
				// ------------------------------
				if (!/^\d{4}-\d{2}-\d{2}$/.test(meetingDate)) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid date format.',
						},
						400,
					);
				}

				// ------------------------------
				// Validate time
				// ------------------------------
				if (!BOOKING_TIMES.includes(meetingTime)) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid meeting time.',
						},
						400,
					);
				}

				// ------------------------------
				// Validate email
				// ------------------------------
				const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

				if (!emailPattern.test(email)) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid email address.',
						},
						400,
					);
				}

				// ------------------------------
				// Check if date is in the past
				// ------------------------------
				const selectedDate = new Date(`${meetingDate}T00:00:00`);

				if (Number.isNaN(selectedDate.getTime())) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid meeting date.',
						},
						400,
					);
				}

				const today = new Date();

				const todayStart = new Date(today.getFullYear(), today.getMonth(), today.getDate());

				if (selectedDate < todayStart) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Meeting date cannot be in the past.',
						},
						400,
					);
				}

				// ------------------------------
				// Save meeting
				// ------------------------------
				try {
					const result = await env.portfolio_messages
						.prepare(
							`
          INSERT INTO meetings
          (
            meeting_date,
            meeting_time,
            name,
            email,
            topic,
            notes,
            timezone,
            status
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, 'scheduled')
        `,
						)
						.bind(meetingDate, meetingTime, name, email, topic, notes, timezone)
						.run();

					return jsonResponse(
						request,
						{
							success: true,
							message: 'Your meeting has been scheduled successfully.',
							id: result.meta.last_row_id,
						},
						201,
					);
				} catch (error) {
					// Duplicate date + time
					if (error?.message?.toLowerCase().includes('unique')) {
						return jsonResponse(
							request,
							{
								success: false,
								message: 'This time slot has already been booked. Please choose another time.',
							},
							409,
						);
					}

					throw error;
				}
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}
		// --------------------------------
		// GET /api/admin/me
		// --------------------------------
		if (request.method === 'GET' && url.pathname === '/api/admin/me') {
			try {
				const session = await getSession(request, env);

				if (!session) {
					return jsonResponse(
						request,
						{
							success: false,
							authenticated: false,
						},
						401,
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
					500,
				);
			}
		}

		// --------------------------------
		// GET /api/admin/meetings
		// --------------------------------
		if (request.method === 'GET' && url.pathname === '/api/admin/meetings') {
			try {
				const session = await getSession(request, env);

				if (!session) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Unauthorized.',
						},
						401,
					);
				}

				const result = await env.portfolio_messages
					.prepare(
						`
        SELECT
          id,
          meeting_date,
          meeting_time,
          name,
          email,
          topic,
          notes,
          timezone,
          status,
          created_at
        FROM meetings
        ORDER BY meeting_date ASC, meeting_time ASC
      `,
					)
					.all();

				return jsonResponse(request, {
					success: true,
					meetings: result.results,
				});
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}
		// --------------------------------
		// PATCH /api/admin/meetings/:id/status
		// --------------------------------

		if (request.method === 'PATCH' && url.pathname.startsWith('/api/admin/meetings/')) {
			try {
				const session = await getSession(request, env);

				if (!session) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Unauthorized.',
						},
						401,
					);
				}

				const meetingId = Number(url.pathname.split('/')[4]);

				if (!Number.isInteger(meetingId)) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid meeting ID.',
						},
						400,
					);
				}

				const body = await request.json();
				const status = body.status?.trim();

				const allowedStatuses = ['scheduled', 'cancelled', 'completed'];

				if (!allowedStatuses.includes(status)) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid status.',
						},
						400,
					);
				}

				const result = await env.portfolio_messages
					.prepare(
						`
        UPDATE meetings
        SET status = ?
        WHERE id = ?
        `,
					)
					.bind(status, meetingId)
					.run();

				if (result.meta.changes === 0) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Meeting not found.',
						},
						404,
					);
				}

				return jsonResponse(request, {
					success: true,
					message: 'Meeting status updated successfully.',
				});
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}
		// --------------------------------
		// GET /api/profile
		// --------------------------------

		if (request.method === 'GET' && url.pathname === '/api/profile') {
			try {
				const result = await env.portfolio_messages
					.prepare(
						`
        SELECT
          id,
          name,
          title,
          bio,
          email,
          github_url,
          telegram_url,
          portfolio_url,
          education,
          skills_json,
          updated_at
        FROM profile
        WHERE id = 1
        `,
					)
					.first();

				if (!result) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Profile not found.',
						},
						404,
					);
				}

				let skills = [];

				try {
					skills = JSON.parse(result.skills_json || '[]');
				} catch {
					skills = [];
				}

				return jsonResponse(request, {
					success: true,
					profile: {
						id: result.id,
						name: result.name,
						title: result.title,
						bio: result.bio,
						email: result.email,
						github_url: result.github_url,
						telegram_url: result.telegram_url,
						portfolio_url: result.portfolio_url,
						education: result.education,
						skills,
						updated_at: result.updated_at,
					},
				});
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}

		// --------------------------------
		// GET /api/admin/profile
		// --------------------------------

		if (request.method === 'GET' && url.pathname === '/api/admin/profile') {
			try {
				const session = await getSession(request, env);

				if (!session) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Unauthorized.',
						},
						401,
					);
				}

				const result = await env.portfolio_messages
					.prepare(
						`
        SELECT
          id,
          name,
          title,
          bio,
          email,
          github_url,
          telegram_url,
          portfolio_url,
          education,
          skills_json,
          updated_at
        FROM profile
        WHERE id = 1
        `,
					)
					.first();

				if (!result) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Profile not found.',
						},
						404,
					);
				}

				let skills = [];

				try {
					skills = JSON.parse(result.skills_json || '[]');
				} catch {
					skills = [];
				}

				return jsonResponse(request, {
					success: true,
					profile: {
						id: result.id,
						name: result.name,
						title: result.title,
						bio: result.bio,
						email: result.email,
						github_url: result.github_url,
						telegram_url: result.telegram_url,
						portfolio_url: result.portfolio_url,
						education: result.education,
						skills,
						updated_at: result.updated_at,
					},
				});
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}

		// --------------------------------
		// PUT /api/admin/profile
		// --------------------------------

		if (request.method === 'PUT' && url.pathname === '/api/admin/profile') {
			try {
				const session = await getSession(request, env);

				if (!session) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Unauthorized.',
						},
						401,
					);
				}

				const body = await request.json();

				const name = body.name?.trim();
				const title = body.title?.trim();
				const bio = body.bio?.trim() || '';
				const email = body.email?.trim() || '';
				const githubUrl = body.github_url?.trim() || '';
				const telegramUrl = body.telegram_url?.trim() || '';
				const portfolioUrl = body.portfolio_url?.trim() || '';
				const education = body.education?.trim() || '';

				const skills = Array.isArray(body.skills) ? body.skills.map((skill) => String(skill).trim()).filter(Boolean) : [];

				if (!name || !title) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Name and title are required.',
						},
						400,
					);
				}

				await env.portfolio_messages
					.prepare(
						`
        UPDATE profile
        SET
          name = ?,
          title = ?,
          bio = ?,
          email = ?,
          github_url = ?,
          telegram_url = ?,
          portfolio_url = ?,
          education = ?,
          skills_json = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
        `,
					)
					.bind(name, title, bio, email, githubUrl, telegramUrl, portfolioUrl, education, JSON.stringify(skills))
					.run();

				return jsonResponse(request, {
					success: true,
					message: 'Profile updated successfully.',
				});
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}
		// --------------------------------
		// GET /api/admin/messages
		// --------------------------------
		if (request.method === 'GET' && url.pathname === '/api/admin/messages') {
			try {
				const session = await getSession(request, env);

				if (!session) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Unauthorized.',
						},
						401,
					);
				}

				const result = await env.portfolio_messages
					.prepare(
						`
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
            `,
					)
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
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}

		// --------------------------------
		// PATCH /api/admin/messages/:id/read
		// --------------------------------
		if (request.method === 'PATCH' && url.pathname.match(/^\/api\/admin\/messages\/\d+\/read$/)) {
			try {
				const session = await getSession(request, env);

				if (!session) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Unauthorized.',
						},
						401,
					);
				}

				const messageId = Number(url.pathname.split('/')[4]);

				if (!Number.isInteger(messageId)) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid message ID.',
						},
						400,
					);
				}

				const result = await env.portfolio_messages
					.prepare(
						`
              UPDATE messages
              SET is_read = 1
              WHERE id = ?
            `,
					)
					.bind(messageId)
					.run();

				if (result.meta.changes === 0) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Message not found.',
						},
						404,
					);
				}

				return jsonResponse(request, {
					success: true,
					message: 'Message marked as read.',
				});
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}

		// --------------------------------
		// DELETE /api/admin/messages/:id
		// --------------------------------
		if (request.method === 'DELETE' && url.pathname.match(/^\/api\/admin\/messages\/\d+$/)) {
			try {
				const session = await getSession(request, env);

				if (!session) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Unauthorized.',
						},
						401,
					);
				}

				const messageId = Number(url.pathname.split('/')[4]);

				if (!Number.isInteger(messageId)) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid message ID.',
						},
						400,
					);
				}

				const result = await env.portfolio_messages
					.prepare(
						`
              DELETE FROM messages
              WHERE id = ?
            `,
					)
					.bind(messageId)
					.run();

				if (result.meta.changes === 0) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Message not found.',
						},
						404,
					);
				}

				return jsonResponse(request, {
					success: true,
					message: 'Message deleted successfully.',
				});
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}

		// --------------------------------
		// POST /api/admin/logout
		// --------------------------------
		if (request.method === 'POST' && url.pathname === '/api/admin/logout') {
			try {
				const cookieHeader = request.headers.get('Cookie');

				if (cookieHeader) {
					const cookies = parseCookies(cookieHeader);

					const token = cookies.admin_session;

					if (token) {
						const tokenHash = await hashToken(token);

						await env.portfolio_messages
							.prepare(
								`
                DELETE FROM admin_sessions
                WHERE token_hash = ?
              `,
							)
							.bind(tokenHash)
							.run();
					}
				}

				const cookie = ['admin_session=', 'HttpOnly', 'Secure', 'SameSite=None', 'Path=/', 'Max-Age=0'].join('; ');

				return jsonResponse(
					request,
					{
						success: true,
						message: 'Logout successful.',
					},
					200,
					{
						'Set-Cookie': cookie,
					},
				);
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}
		// --------------------------------
		// GET /api/meetings/availability
		// --------------------------------
		if (request.method === 'GET' && url.pathname === '/api/meetings/availability') {
			try {
				const date = url.searchParams.get('date');

				if (!date) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Date is required.',
						},
						400,
					);
				}

				// Validate YYYY-MM-DD
				if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
					return jsonResponse(
						request,
						{
							success: false,
							message: 'Invalid date format.',
						},
						400,
					);
				}

				const result = await env.portfolio_messages
					.prepare(
						`
        SELECT meeting_time
        FROM meetings
        WHERE meeting_date = ?
        AND status = 'scheduled'
      `,
					)
					.bind(date)
					.all();

				const bookedTimes = result.results.map((meeting) => meeting.meeting_time);

				const availableTimes = BOOKING_TIMES.filter((time) => !bookedTimes.includes(time));

				return jsonResponse(request, {
					success: true,
					date,
					availableTimes,
				});
			} catch (error) {
				console.error(error);

				return jsonResponse(
					request,
					{
						success: false,
						message: 'Something went wrong.',
					},
					500,
				);
			}
		}
		// --------------------------------
		// Default
		// --------------------------------
		return jsonResponse(request, {
			success: true,
			message: 'Portfolio API is running.',
		});
	},
};
