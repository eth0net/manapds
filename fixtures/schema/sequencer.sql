CREATE INDEX "repo_seq_did_idx" on "repo_seq" ("did");
CREATE INDEX "repo_seq_event_type_idx" on "repo_seq" ("eventType");
CREATE INDEX "repo_seq_sequenced_at_index" on "repo_seq" ("sequencedAt");
CREATE TABLE "kysely_migration_lock" ("id" varchar(255) not null primary key, "is_locked" integer default 0 not null);
CREATE TABLE "kysely_migration" ("name" varchar(255) not null primary key, "timestamp" varchar(255) not null);
CREATE TABLE "repo_seq" ("seq" integer primary key autoincrement, "did" varchar not null, "eventType" varchar not null, "event" blob not null, "invalidated" int2 default 0 not null, "sequencedAt" varchar not null);
