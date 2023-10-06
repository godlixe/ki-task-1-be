init:
	docker compose build && docker compose up -d

start:
	docker compose up -d

stop:
	docker compose stop

restart:
	docker compose down && docker compose up -d

update:
	docker compose down && docker compose build && docker compose up -d
