CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    user_id INT,
    filename VARCHAR(255) NOT NULL,
    type VARCHAR(25) NOT NULL,
    filepath VARCHAR(255) NOT NULL,
    key_reference BYTEA,
    CONSTRAINT fk_users FOREIGN KEY (user_id) REFERENCES users(id)
)
