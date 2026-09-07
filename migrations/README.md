# Database Migrations

This directory contains SQL migrations for the PostgreSQL database.

We use [golang-migrate](https://github.com/golang-migrate/migrate) for migration management.

## Running Migrations

To apply migrations:
```bash
migrate -path ./migrations -database "postgres://user:password@localhost:5432/dbname?sslmode=disable" up
```

To rollback the last migration:
```bash
migrate -path ./migrations -database "postgres://user:password@localhost:5432/dbname?sslmode=disable" down
```

## Migration Files

Migration files should be named as:
- `{version}_{description}.up.sql` for upward migrations
- `{version}_{description}.down.sql` for downward migrations

Example:
- `001_create_users_table.up.sql`
- `001_create_users_table.down.sql`