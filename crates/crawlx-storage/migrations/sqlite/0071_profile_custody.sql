-- Keep one retained-profile namespace; wrapped keys never contain plaintext keys.
ALTER TABLE browser_profiles ADD COLUMN custody_format INTEGER NOT NULL DEFAULT 0 CHECK(custody_format IN (0,1));
ALTER TABLE browser_profiles ADD COLUMN custody_artifact BLOB CHECK(custody_artifact IS NULL OR length(custody_artifact)=16);
ALTER TABLE browser_profiles ADD COLUMN custody_envelope TEXT CHECK(custody_envelope IS NULL OR (json_valid(custody_envelope) AND json_type(custody_envelope)='object' AND length(CAST(custody_envelope AS BLOB))<=400000));
ALTER TABLE browser_profiles ADD COLUMN custody_incarnation BLOB CHECK(custody_incarnation IS NULL OR (length(custody_incarnation)=16 AND custody_incarnation<>zeroblob(16)));
ALTER TABLE browser_profiles ADD COLUMN custody_epoch INTEGER CHECK(custody_epoch IS NULL OR (custody_epoch>0 AND custody_epoch<9007199254740000));
CREATE UNIQUE INDEX browser_profiles_custody_artifact ON browser_profiles(custody_artifact) WHERE custody_format=1;
CREATE TRIGGER browser_profiles_custody_shape_insert BEFORE INSERT ON browser_profiles
WHEN NOT (
  (NEW.custody_format=0 AND NEW.custody_artifact IS NULL AND NEW.custody_envelope IS NULL AND NEW.custody_incarnation IS NULL AND NEW.custody_epoch IS NULL)
  OR (NEW.custody_format=1 AND NEW.custody_artifact IS NOT NULL AND NEW.custody_envelope IS NOT NULL AND NEW.custody_incarnation IS NOT NULL AND NEW.custody_epoch IS NOT NULL)
) BEGIN SELECT RAISE(ABORT,'invalid profile custody shape'); END;
CREATE TRIGGER browser_profiles_custody_shape_update BEFORE UPDATE ON browser_profiles
WHEN NOT (
  (NEW.custody_format=0 AND NEW.custody_artifact IS NULL AND NEW.custody_envelope IS NULL AND NEW.custody_incarnation IS NULL AND NEW.custody_epoch IS NULL)
  OR (NEW.custody_format=1 AND NEW.custody_artifact IS NOT NULL AND NEW.custody_envelope IS NOT NULL AND NEW.custody_incarnation IS NOT NULL AND NEW.custody_epoch IS NOT NULL)
) BEGIN SELECT RAISE(ABORT,'invalid profile custody shape'); END;
