CREATE TABLE IF NOT EXISTS profile_notifications (
    id SERIAL PRIMARY KEY,
    source_user_id INT,
    target_user_id INT,
    status INT
)
