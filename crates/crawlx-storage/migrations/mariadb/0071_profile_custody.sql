-- Extend the sole retained-profile namespace with separately wrapped key custody.
ALTER TABLE browser_profiles DROP CONSTRAINT IF EXISTS browser_profiles_custody_shape;
ALTER TABLE browser_profiles
  ADD COLUMN IF NOT EXISTS custody_format INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS custody_artifact BINARY(16) NULL,
  ADD COLUMN IF NOT EXISTS custody_envelope LONGTEXT NULL,
  ADD COLUMN IF NOT EXISTS custody_incarnation BINARY(16) NULL,
  ADD COLUMN IF NOT EXISTS custody_epoch BIGINT NULL,
  ADD CONSTRAINT browser_profiles_custody_shape CHECK (
    (custody_format=0 AND custody_artifact IS NULL AND custody_envelope IS NULL
      AND custody_incarnation IS NULL AND custody_epoch IS NULL)
    OR
    (custody_format=1 AND custody_artifact IS NOT NULL AND custody_envelope IS NOT NULL
      AND custody_incarnation IS NOT NULL AND custody_incarnation<>UNHEX(REPEAT('00',16))
      AND custody_epoch IS NOT NULL AND custody_epoch>0 AND custody_epoch<9007199254740000
      AND JSON_VALID(custody_envelope) AND JSON_TYPE(custody_envelope)='OBJECT'
      AND OCTET_LENGTH(custody_envelope)<=400000)
  );
CREATE UNIQUE INDEX IF NOT EXISTS browser_profiles_custody_artifact
  ON browser_profiles (custody_artifact);
