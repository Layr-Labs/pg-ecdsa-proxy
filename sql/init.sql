-- Initial schema for ECDSA-authenticated Postgres

CREATE TABLE IF NOT EXISTS example_data (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert sample data
INSERT INTO example_data (content) VALUES 
    ('Hello from ECDSA-authenticated Postgres!'),
    ('This data is protected by signature verification.');
