-- Route-level state coarsening is explicit durable coverage metadata.
ALTER TABLE action_contexts ADD COLUMN coarsened boolean NOT NULL DEFAULT false;
