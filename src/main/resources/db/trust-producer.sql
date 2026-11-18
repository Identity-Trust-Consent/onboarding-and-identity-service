-- Run on the onboarding/identity database before enabling the trust producer.
create table if not exists trust_signal_outbox (
  event_id uuid primary key,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  delivered_at timestamptz,
  attempts integer not null default 0
);
create index if not exists idx_trust_signal_outbox_pending on trust_signal_outbox(created_at) where delivered_at is null;
