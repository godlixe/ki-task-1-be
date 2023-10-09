CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    type VARCHAR(25) NOT NULL,
    filepath VARCHAR(255) NOT NULL,
    metadata BYTEA
)
