ALTER TABLE public.properties
  ADD COLUMN IF NOT EXISTS availability_status TEXT,
  ADD COLUMN IF NOT EXISTS availability_checked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS unlock_count_since_check INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS current_lease_end DATE;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'properties_availability_status_check'
      AND conrelid = 'public.properties'::regclass
  ) THEN
    ALTER TABLE public.properties
      ADD CONSTRAINT properties_availability_status_check
      CHECK (
        availability_status IS NULL
        OR availability_status IN (
          'AVAILABLE',
          'PAUSED_CHECK',
          'OCCUPIED',
          'COMING_SOON',
          'DAMAGED',
          'UNVERIFIED_EXPIRED'
        )
      );
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'properties_unlock_count_nonnegative_check'
      AND conrelid = 'public.properties'::regclass
  ) THEN
    ALTER TABLE public.properties
      ADD CONSTRAINT properties_unlock_count_nonnegative_check
      CHECK (unlock_count_since_check >= 0);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_properties_availability_expiry
  ON public.properties (expires_at)
  WHERE availability_status = 'AVAILABLE' AND expires_at IS NOT NULL;

COMMENT ON COLUMN public.properties.availability_status IS
  'New availability lifecycle; NULL means legacy/unclassified and is not a public availability decision.';
COMMENT ON COLUMN public.properties.availability_checked_at IS
  'When the owner last confirmed the listing was available.';
COMMENT ON COLUMN public.properties.expires_at IS
  'Availability verification expiry; NULL means no expiry has been established.';
