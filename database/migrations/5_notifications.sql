CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    source_user_id INT,
    target_user_id INT,
    file_id INT,
    status INT,
    CONSTRAINT fk_files FOREIGN KEY (file_id) REFERENCES files(id)
)
