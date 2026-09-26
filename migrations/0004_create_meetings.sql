-- Migration number: 0004 	 2026-09-26T16:47:34.436Z
CREATE TABLE IF NOT EXISTS meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    meeting_date TEXT NOT NULL,
    meeting_time TEXT NOT NULL,

    name TEXT NOT NULL,
    email TEXT NOT NULL,

    topic TEXT,
    notes TEXT,

    timezone TEXT,

    status TEXT NOT NULL DEFAULT 'scheduled',

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (meeting_date, meeting_time)
);

CREATE INDEX IF NOT EXISTS idx_meetings_date
ON meetings(meeting_date);

CREATE INDEX IF NOT EXISTS idx_meetings_status
ON meetings(status);
