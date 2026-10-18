CREATE TABLE "did_doc" ("did" varchar primary key, "doc" text not null, "updatedAt" bigint not null);
CREATE TABLE "kysely_migration_lock" ("id" varchar(255) not null primary key, "is_locked" integer default 0 not null);
CREATE TABLE "kysely_migration" ("name" varchar(255) not null primary key, "timestamp" varchar(255) not null);
