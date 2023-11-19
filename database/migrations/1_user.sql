CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone_number VARCHAR(255) NOT NULL,
    gender VARCHAR(255) NOT NULL,
    religion VARCHAR(255) NOT NULL,
    nationality VARCHAR(255) NOT NULL,
    address VARCHAR(255) NOT NULL,
    birth_info VARCHAR(255) NOT NULL,
    public_key VARCHAR NOT NULL,
    private_key VARCHAR NOT NULL,
    key_reference BYTEA NOT NULL
)
