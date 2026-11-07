-- One hash is one bounded run incarnation. Lifetime changes require an explicit
-- durable renewal barrier. No plaintext fallback or implicit resurrection.
local key = KEYS[1]
local action, incarnation = ARGV[1], ARGV[2]
local expected, operation, value, deadline = ARGV[3], ARGV[4], ARGV[5], tonumber(ARGV[6])
local max_values, max_bytes, max_value = 256, 1048576, 16384
local max_epoch = 9007199254740000
local function denied() return {'denied'} end
-- Lifetime mutation cannot atomically observe PostgreSQL revocation/fencing.
-- Reject even delayed commands; only historical exact proofs remain readable.
if action == 'renew' or action == 'renew_prepare' then return denied() end
if action == 'init' and redis.call('EXISTS', key) == 0 then
    local now = redis.call('TIME')
    local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
    if not deadline or deadline <= now_ms or deadline > now_ms + 86400000 then return denied() end
    if not ARGV[7] or #ARGV[7] ~= 36 then return denied() end
    redis.call('HSET', key, 'incarnation', incarnation, 'epoch', '1', 'count', '0', 'bytes', '0', 'operation', operation, 'value', '', 'salt', ARGV[7])
    redis.call('PEXPIREAT', key, deadline)
end
if redis.call('TYPE', key).ok ~= 'hash' or redis.call('PTTL', key) <= 0 then return denied() end
if redis.call('HGET', key, 'incarnation') ~= incarnation then return denied() end
local epoch_text = redis.call('HGET', key, 'epoch')
local epoch = tonumber(epoch_text)
local count = tonumber(redis.call('HGET', key, 'count'))
local size = tonumber(redis.call('HGET', key, 'bytes'))
if not epoch or epoch < 1 or epoch > max_epoch or epoch ~= math.floor(epoch) or tostring(epoch) ~= epoch_text then return denied() end
if not count or count < 0 or count > max_values or count ~= math.floor(count) then return denied() end
if not size or size < 0 or size > max_bytes or size ~= math.floor(size) then return denied() end
local renewal_operation = redis.call('HGET', key, 'renewal_operation')
local renewal_deadline_text = redis.call('HGET', key, 'renewal_deadline')
local renewal_previous_text = redis.call('HGET', key, 'renewal_previous')
local renewal_fields = 0
if renewal_operation or renewal_deadline_text or renewal_previous_text then
    local renewal_deadline, renewal_previous = tonumber(renewal_deadline_text), tonumber(renewal_previous_text)
    if not renewal_operation or #renewal_operation ~= 36 or not renewal_deadline or not renewal_previous
        or renewal_deadline ~= math.floor(renewal_deadline) or renewal_previous ~= math.floor(renewal_previous)
        or tostring(renewal_deadline) ~= renewal_deadline_text or tostring(renewal_previous) ~= renewal_previous_text
        or renewal_previous <= 0 or renewal_deadline <= renewal_previous
        or renewal_deadline - renewal_previous > 86400000
        or redis.call('PEXPIRETIME', key) ~= renewal_deadline then return denied() end
    renewal_fields = 3
end
if redis.call('HLEN', key) ~= 7 + count + renewal_fields then return denied() end
local salt = redis.call('HGET', key, 'salt')
if not salt or #salt ~= 36 then return denied() end
local values, measured = {}, 0
for i = 1, count do
    local secret = redis.call('HGET', key, 's' .. tostring(i))
    if not secret or #secret < 1 or #secret > max_value then return denied() end
    measured = measured + #secret
    table.insert(values, secret)
end
if measured ~= size or not redis.call('HGET', key, 'operation') or not redis.call('HGET', key, 'value') then return denied() end
if action == 'init' then
    if epoch ~= 1 or count ~= 0 or redis.call('HGET', key, 'operation') ~= operation then return denied() end
elseif action == 'prepare' then
    -- Never mutate before Rust checks the durable pending commitment. Recovery
    -- accepts either the untouched old epoch or the already-applied exact value.
    if epoch_text ~= expected then
        if epoch ~= tonumber(expected) + 1 or redis.call('HGET', key, 'operation') ~= operation
            or redis.call('HGET', key, 'value') ~= value then return denied() end
    end
elseif action == 'register' then
    if epoch == tonumber(expected) + 1 and redis.call('HGET', key, 'operation') == operation then
        if redis.call('HGET', key, 'value') ~= value then return denied() end
    else
        if epoch_text ~= expected or epoch >= max_epoch or #value < 1 or #value > max_value then return denied() end
        local duplicate = false
        for _, secret in ipairs(values) do if secret == value then duplicate = true end end
        if not duplicate then
            if count >= max_values or size + #value > max_bytes then return denied() end
            count, size = count + 1, size + #value
            redis.call('HSET', key, 's' .. tostring(count), value, 'count', tostring(count), 'bytes', tostring(size))
            table.insert(values, value)
        end
        epoch = epoch + 1
        redis.call('HSET', key, 'epoch', tostring(epoch), 'operation', operation, 'value', value)
    end
elseif action == 'renew_recover' then
    -- Keep registration's operation/value and the complete secret epoch intact.
    -- The metadata is separate and never enters the secret-set commitment.
    local previous = tonumber(value)
    if epoch_text ~= expected or #operation ~= 36 or not previous or not deadline
        or previous ~= math.floor(previous) or tostring(previous) ~= value
        or deadline ~= math.floor(deadline) or previous <= 0
        or deadline <= previous or deadline - previous > 86400000 then return denied() end
    local exact = renewal_operation == operation and renewal_deadline_text == tostring(deadline)
        and renewal_previous_text == value
    local now = redis.call('TIME')
    local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
    if deadline <= now_ms then return denied() end
    -- Read-only proof at every time, never an unapplied extension.
    if not exact then return denied() end
elseif action == 'snapshot' then
    if epoch_text ~= expected then return denied() end
else
    return denied()
end
local result = {'ok', tostring(epoch), salt}
for _, secret in ipairs(values) do table.insert(result, secret) end
return result
