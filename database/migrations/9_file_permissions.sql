CREATE TABLE IF NOT EXISTS file_permissions (
    id SERIAL PRIMARY KEY,
    filepath VARCHAR(255) NOT NULL,
    permission_id INT,
    file_id INT,
    CONSTRAINT fk_files FOREIGN KEY (file_id) REFERENCES files(id),
    CONSTRAINT fk_permissions FOREIGN KEY (permission_id) REFERENCES permissions(id)
)
