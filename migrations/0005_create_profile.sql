CREATE TABLE IF NOT EXISTS profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),

    name TEXT NOT NULL,
    title TEXT NOT NULL,
    bio TEXT,

    email TEXT,
    github_url TEXT,
    telegram_url TEXT,
    portfolio_url TEXT,

    education TEXT,

    skills_json TEXT NOT NULL DEFAULT '[]',

    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO profile (
    id,
    name,
    title,
    bio,
    email,
    github_url,
    telegram_url,
    portfolio_url,
    education,
    skills_json
)
VALUES (
    1,
    'Mohammad Mehdi Sasanian',
    'Frontend / React Developer',
    'Frontend developer focused on building modern and responsive web applications with React and JavaScript.',
    '',
    'https://github.com/iamsasani',
    '',
    'https://personal-portfolio.workwithsasan.workers.dev/',
    'B.Sc. Computer Engineering — Software Engineering — Islamic Azad University, Marvdasht Branch',
    '["HTML","CSS","JavaScript","React","Tailwind CSS","REST API","Context API","Cloudflare Workers","Cloudflare D1","Git & GitHub"]'
);
