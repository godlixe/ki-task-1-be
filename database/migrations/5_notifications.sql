CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    source_user_id INT,
    target_user_id INT,
    status INT
)
