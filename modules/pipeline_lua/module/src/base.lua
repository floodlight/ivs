local bit = require("bit")
local ffi = require("ffi")
local C = ffi.C

local sandbox = {
    assert=assert,
    error=error,
    _G=sandbox,
    ipairs=ipairs,
    next=next,
    pairs=pairs,
    pcall=pcall,
    select=select,
    -- setmetatable is only safe as long as we include a __metatable
    -- field in our own metatables, to prevent untrusted code from
    -- changing them.
    setmetatable=setmetatable,
    tonumber=tonumber,
    tostring=tostring,
    type=type,
    unpack=unpack,
    _VERSION=_VERSION,
    xpcall=xpcall,

    bit=bit,
    ffi=ffi, -- UNSAFE

    string={
        byte=string.byte,
        char=string.char,
        find=string.find,
        format=string.format,
        gmatch=string.gmatch,
        gsub=string.gsub,
        len=string.len,
        lower=string.lower,
        match=string.match,
        rep=string.rep,
        reverse=string.reverse,
        sub=string.sub,
        upper=string.upper,
    },

    table={
        concat=table.concat,
        insert=table.insert,
        max=table.maxn,
        remove=table.remove,
        sort=table.sort,
    },

    os={
        clock=os.clock,
    },

    field_names=field_names,
    register_table=register_table,
}

_G.sandbox = sandbox -- global for C to use

-- To be overridden by uploaded code
function sandbox.ingress() end

-- Entrypoint for packet processing
function process()
    sandbox.ingress()
end

function sandbox.require(name)
    return sandbox[name]
end

function sandbox.loadstring(s, name)
    return setfenv(loadstring(s, name), sandbox)
end

ffi.cdef[[
void pipeline_lua_log(const char *str);
]]

function sandbox.log(...)
    C.pipeline_lua_log(string.format(...))
end

---- Context

-- Create a struct declaration for the field names given to us by C
do
    local lines = {}
    table.insert(lines, "struct fields {")
    for i, v in ipairs(field_names) do
        table.insert(lines, string.format("uint32_t %s;", v))
    end
    table.insert(lines, "};")
    local str = table.concat(lines, "\n")
    ffi.cdef(str)
end

ffi.cdef[[
struct xbuf;
struct action_context;

struct context {
    struct xbuf *stats;
    struct action_context *actx;
    struct fields fields;
};
]]

context = ffi.cast(ffi.typeof('struct context *'), _context)

-- Create a safe proxy for the raw fields pointer
sandbox.fields = setmetatable({}, { __index=context.fields, __metatable=true })
