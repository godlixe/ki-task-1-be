CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    source_user_id INT,
    target_user_id INT,
    key BYTEA,
    key_reference BYTEA
)
