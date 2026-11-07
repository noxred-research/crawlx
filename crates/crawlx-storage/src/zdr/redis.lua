-- Dedicated volatile Redis namespace. All keys share the {delivery} hash tag.
-- Content lives only in per-page hashes with a first-insert native expiry.
-- Global indexes have no content and expire at the latest live page deadline.
local action = ARGV[1]
local now = tonumber(ARGV[2])
local max_entries = tonumber(ARGV[3])
local max_bytes = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local prefix = ARGV[6]
local tenant = ARGV[7]
local run = ARGV[8]
local page = ARGV[9]
local kind = ARGV[10]
local wire = ARGV[11]
local artifact = ARGV[12]
local size = tonumber(ARGV[13])
local inserted = ARGV[14]
local expires = ARGV[15]
local deadline = tonumber(ARGV[16])
local bytes = ARGV[17]
local page_key = prefix .. tenant .. ':' .. run .. ':' .. page
local time = redis.call('TIME')
local server_now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

local function remove_page(key)
    local ids = redis.call('HGET', KEYS[6], key)
    if ids then
        for _, id in ipairs(cjson.decode(ids)) do
            redis.call('HDEL', KEYS[5], id)
        end
    end
    local old_size = tonumber(redis.call('HGET', KEYS[2], key) or '0')
    if old_size > 0 then redis.call('DECRBY', KEYS[9], old_size) end
    redis.call('DEL', key)
    redis.call('ZREM', KEYS[1], key)
    redis.call('ZREM', KEYS[3], key)
    redis.call('ZREM', KEYS[4], key)
    redis.call('HDEL', KEYS[2], key)
    redis.call('HDEL', KEYS[6], key)
end

local function sweep_index(index, at)
    local expired = redis.call('ZRANGEBYSCORE', index, '-inf', at)
    for _, key in ipairs(expired) do remove_page(key) end
    return #expired
end

local function finalize()
    local last = redis.call('ZRANGE', KEYS[4], -1, -1, 'WITHSCORES')
    if #last == 0 then
        for _, key in ipairs(KEYS) do redis.call('DEL', key) end
    else
        local last_deadline = tonumber(last[2])
        for _, key in ipairs(KEYS) do redis.call('PEXPIREAT', key, last_deadline) end
    end
end

local function live(key)
    local expiry = tonumber(redis.call('ZSCORE', KEYS[3], key) or '0')
    return expiry > now and redis.call('EXISTS', key) == 1
end

local function read_page(key)
    if not live(key) then return false end
    local header = redis.call('HMGET', key, 'tenant', 'run', 'page', 'inserted', 'expires')
    local fields = redis.call('HKEYS', key)
    local blobs = {}
    for _, field in ipairs(fields) do
        if string.sub(field, 1, 2) == 'b:' then
            local rendition = string.sub(field, 3)
            table.insert(blobs, {rendition, redis.call('HGET', key, field),
                redis.call('HGET', key, 'v:' .. rendition)})
        end
    end
    table.insert(header, blobs)
    return header
end

-- Server-side TTL may already have removed page hashes. Remove their accounting
-- before any action, without turning an injected-clock read into an expiry sweep.
local native_removed = sweep_index(KEYS[4], server_now)
if action == 'sweep' or action == 'insert' or action == 'startup' then
    native_removed = native_removed + sweep_index(KEYS[3], now)
end

if action == 'insert' or action == 'startup' then
    local configured = redis.call('HMGET', KEYS[8], 'max_entries', 'max_bytes')
    if redis.call('ZCARD', KEYS[1]) > 0 and
        ((configured[1] and tonumber(configured[1]) ~= max_entries) or
         (configured[2] and tonumber(configured[2]) ~= max_bytes)) then
        return redis.error_reply('ZDR_LIMITS_MISMATCH')
    end
    redis.call('HSET', KEYS[8], 'max_entries', max_entries, 'max_bytes', max_bytes)
end

if action == 'insert' then
    if size ~= #bytes then return redis.error_reply('ZDR_CONTENT_SIZE_MISMATCH') end
    if max_entries == 0 or size > max_bytes then
        finalize()
        return 'RENDITION_TOO_LARGE'
    end
    local exists = redis.call('EXISTS', page_key) == 1
    if exists then
        local remaining = redis.call('PTTL', page_key)
        if remaining < 0 or remaining > 3600000 or
            not redis.call('ZSCORE', KEYS[1], page_key) then
            return redis.error_reply('ZDR_PAGE_EXPIRY_OR_ACCOUNTING_INVALID')
        end
        local original_deadline = tonumber(redis.call('ZSCORE', KEYS[3], page_key) or '0')
        if original_deadline > deadline then
            return redis.error_reply('ZDR_ORIGINAL_EXPIRY_EXTENSION')
        end
    end
    local old_page_size = tonumber(redis.call('HGET', KEYS[2], page_key) or '0')
    local old_blob_size = tonumber(redis.call('HGET', page_key, 's:' .. kind) or '0')
    local new_size = old_page_size - old_blob_size + size
    if new_size > max_bytes then
        remove_page(page_key)
        finalize()
        return 'PAGE_TOO_LARGE'
    end
    local old_id = redis.call('HGET', page_key, 'id:' .. kind)
    local old_wire = tonumber(redis.call('HGET', page_key, 'w:' .. kind) or '0')
    local new_wire = tonumber(redis.call('HGET', page_key, 'wire_bytes') or '0') - old_wire + #wire + #kind
    local ids = {}
    local encoded_ids = redis.call('HGET', KEYS[6], page_key)
    if encoded_ids then
        for _, id in ipairs(cjson.decode(encoded_ids)) do
            if id ~= old_id then table.insert(ids, id) end
        end
    end
    table.insert(ids, artifact)
    encoded_ids = cjson.encode(ids)
    if new_wire > 1048576 or #encoded_ids > 65536 then
        finalize()
        return 'METADATA_TOO_LARGE'
    end
    local sequence = tonumber(redis.call('GET', KEYS[7]) or '0')
    if not exists and sequence >= 9007199254740990 then
        return redis.error_reply('ZDR_SEQUENCE_EXHAUSTED')
    end
    -- Reserve capacity atomically, preserving this page until replacement commits.
    local count = redis.call('ZCARD', KEYS[1]) - (exists and 1 or 0) + 1
    local total = tonumber(redis.call('GET', KEYS[9]) or '0') - old_page_size + new_size
    while count > max_entries or total > max_bytes do
        local oldest = redis.call('ZRANGE', KEYS[1], 0, 1)
        local victim = oldest[1]
        if victim == page_key then victim = oldest[2] end
        if not victim then return redis.error_reply('ZDR_CAPACITY_ACCOUNTING_INVALID') end
        local victim_size = tonumber(redis.call('HGET', KEYS[2], victim) or '0')
        remove_page(victim)
        count = count - 1
        total = total - victim_size
    end
    if not exists then
        sequence = redis.call('INCR', KEYS[7])
        redis.call('HSET', page_key, 'tenant', tenant, 'run', run, 'page', page,
            'inserted', inserted, 'expires', expires)
        -- Assign native expiry before writing any rendition bytes or arbitrary
        -- metadata. A later command/ACL failure must never leave immortal content.
        local native_deadline = server_now + math.max(1, math.min(ttl, deadline - now))
        redis.call('PEXPIREAT', page_key, native_deadline)
        redis.call('ZADD', KEYS[1], sequence, page_key)
        redis.call('ZADD', KEYS[3], deadline, page_key)
        redis.call('ZADD', KEYS[4], native_deadline, page_key)
    end
    redis.call('HSET', page_key,
        'b:' .. kind, wire, 'v:' .. kind, bytes, 's:' .. kind, size,
        'id:' .. kind, artifact, 'a:' .. artifact, kind,
        'w:' .. kind, #wire + #kind, 'wire_bytes', new_wire)
    if old_id then
        redis.call('HDEL', KEYS[5], old_id)
        redis.call('HDEL', page_key, 'a:' .. old_id)
    end
    -- Global locators carry only identifiers. Arbitrary kinds stay inside the
    -- natively expiring page hash, never in an incompletely finalized index.
    redis.call('HSET', KEYS[5], artifact, page_key)
    redis.call('HSET', KEYS[6], page_key, encoded_ids)
    redis.call('HSET', KEYS[2], page_key, new_size)
    redis.call('INCRBY', KEYS[9], new_size - old_page_size)
    finalize()
    return 'OK'
end

if action == 'get' then
    local result = read_page(page_key)
    finalize()
    return result
elseif action == 'content_metadata' then
    local result = false
    if live(page_key) then
        local rendition = redis.call('HGET', page_key, 'a:' .. artifact)
        if rendition then
            result = {redis.call('HGET', page_key, 'expires'),
                redis.call('HGET', page_key, 'b:' .. rendition),
                redis.call('HSTRLEN', page_key, 'v:' .. rendition)}
        end
    end
    finalize()
    return result
elseif action == 'content_deadline' then
    local result = false
    if live(page_key) and redis.call('HEXISTS', page_key, 'a:' .. artifact) == 1 then
        result = redis.call('HGET', page_key, 'expires')
    end
    finalize()
    return result
elseif action == 'find' then
    local locator = redis.call('HGET', KEYS[5], artifact)
    local result = false
    if locator then
        if live(locator) then
            local scope = redis.call('HMGET', locator, 'tenant', 'run')
            if tenant == '' or (scope[1] == tenant and scope[2] == run) then
                local rendition = redis.call('HGET', locator, 'a:' .. artifact)
                if not rendition then return redis.error_reply('ZDR_ARTIFACT_INDEX_INVALID') end
                if redis.call('HSTRLEN', locator, 'v:' .. rendition) > size then
                    return redis.error_reply('ZDR_CONTENT_READ_LIMIT')
                end
                result = {redis.call('HGET', locator, 'b:' .. rendition),
                    redis.call('HGET', locator, 'v:' .. rendition)}
            end
        end
    end
    finalize()
    return result
elseif action == 'list' then
    local results = {}
    for _, key in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
        local scope = redis.call('HMGET', key, 'tenant', 'run')
        if scope[1] == tenant and scope[2] == run then
            local result = read_page(key)
            if result then table.insert(results, result) end
        end
    end
    finalize()
    return results
elseif action == 'ack' then
    local held = redis.call('ZSCORE', KEYS[1], page_key) and 1 or 0
    remove_page(page_key)
    finalize()
    return held
elseif action == 'purge' or action == 'purge_run_id' then
    local removed = 0
    for _, key in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
        local scope = redis.call('HMGET', key, 'tenant', 'run')
        if scope[2] == run and (action == 'purge_run_id' or scope[1] == tenant) then
            remove_page(key)
            removed = removed + 1
        end
    end
    finalize()
    return removed
elseif action == 'stats' then
    local result = {redis.call('ZCARD', KEYS[1]), tonumber(redis.call('GET', KEYS[9]) or '0')}
    finalize()
    return result
elseif action == 'sweep' or action == 'startup' then
    finalize()
    return native_removed
end
return redis.error_reply('ZDR_UNKNOWN_ACTION')
