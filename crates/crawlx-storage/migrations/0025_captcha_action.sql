-- Explicit CAPTCHA solves use the same action journal and safety decisions as user input.
ALTER TYPE action_kind ADD VALUE IF NOT EXISTS 'solve_captcha';
