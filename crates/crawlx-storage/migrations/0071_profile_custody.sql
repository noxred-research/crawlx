-- Cookie and web-storage custody shares the existing retained-profile namespace.
-- Legacy directory bundles remain distinguishable and cannot enter custody APIs.
ALTER TABLE browser_profiles
  ADD COLUMN custody_format integer NOT NULL DEFAULT 0,
  ADD COLUMN custody_artifact uuid,
  ADD COLUMN custody_envelope jsonb,
  ADD COLUMN custody_incarnation uuid,
  ADD COLUMN custody_epoch bigint,
  ADD CONSTRAINT browser_profiles_custody_shape CHECK (
    (custody_format=0 AND custody_artifact IS NULL AND custody_envelope IS NULL
      AND custody_incarnation IS NULL AND custody_epoch IS NULL)
    OR
    (custody_format=1 AND custody_artifact IS NOT NULL AND custody_envelope IS NOT NULL
      AND custody_incarnation IS NOT NULL AND custody_incarnation<>'00000000-0000-0000-0000-000000000000'::uuid
      AND custody_epoch IS NOT NULL AND custody_epoch>0 AND custody_epoch<9007199254740000
      AND jsonb_typeof(custody_envelope)='object'
      AND octet_length(custody_envelope::text)<=400000)
  );
CREATE UNIQUE INDEX browser_profiles_custody_artifact
  ON browser_profiles(custody_artifact) WHERE custody_format=1;
