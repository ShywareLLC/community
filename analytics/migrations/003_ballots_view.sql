-- Migration 003: no joined ballot materialization.
--
-- The current protocol emits submission_accepted events with scoping_id only.
-- It does not emit a queryable event that contains both voter identity and
-- ballot payload, and analytics must not recreate the old voter_tag + choice
-- shape. List-specific read models are introduced in migration 005.

DROP MATERIALIZED VIEW IF EXISTS ballots_view CASCADE;

DROP FUNCTION IF EXISTS refresh_ballots_view();
