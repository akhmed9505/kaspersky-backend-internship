CREATE TABLE threats (
    md5 text CONSTRAINT threats_pkey PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    severity text NOT NULL DEFAULT 'unknown',
    file_type text,
    first_seen_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT threats_md5_check CHECK (
        char_length(md5) = 32 AND md5 ~ '^[a-f0-9]{32}$'
    ),
    CONSTRAINT threats_name_check CHECK (char_length(name) BETWEEN 1 AND 255),
    CONSTRAINT threats_description_check CHECK (char_length(description) <= 4096),
    CONSTRAINT threats_severity_check CHECK (
        severity IN ('unknown', 'low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT threats_file_type_check CHECK (
        file_type IS NULL OR (
            char_length(file_type) BETWEEN 1 AND 32
            AND file_type ~ '^[a-z0-9][a-z0-9._+-]{0,31}$'
        )
    ),
    CONSTRAINT threats_first_seen_at_check CHECK (
        first_seen_at IS NULL OR (
            first_seen_at >= TIMESTAMPTZ '0001-01-01 00:00:00+00'
            AND first_seen_at < TIMESTAMPTZ '10000-01-01 00:00:00+00'
        )
    )
);
