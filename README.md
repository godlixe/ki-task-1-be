# ki-task-1-be

## Prerequisite
- Install `makefile` in your computer

## How to start
1. Run `make init` in terminal
2. Access the container's postgresql CLI by running the command `docker exec -it [container_name] psql -U [postgres_username]` and enter the password.
3. Run the migration scripts in `database/migrations` directory to the docker's postgresql CLI. 
4. Access API in `localhost:8080`
