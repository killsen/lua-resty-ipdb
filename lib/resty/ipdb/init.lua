-- Copyright (C) Peter Zhu (starsz), UPYUN Inc.
-- forked from https://github.com/starsz/lua-resty-ipdb

local bit       = require "bit"
local cjson     = require "cjson.safe"

local band      = bit.band
local lshift    = bit.lshift
local rshift    = bit.rshift

local _match    = ngx.re.match
local _split    = require "ngx.re".split
local _byte     = string.byte
local _sub      = string.sub

local _T = {}
local _M = { _VERSION = "0.1.1", types = _T }
local mt = { __index = _M }

local IPV4                 = 1
local IPV6                 = 2

local INVALID_FILE_PATH    = "invalid file path"
local INVALID_DB_FORMAT    = "invalid db format"
local LANGUAGE_ERR         = "language not support"
local DATABASE_ERR         = "database error"

local ipv4_pattern  = [[(((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))\.){3}((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))]]

-- 试用版IP地址数据库下载
-- https://www.ipip.net/download.html

-- 使用同目录下的 ipipfree.ipdb
local function get_ipipfree_ipdb()

    local info = debug.getinfo(1, "S")
    local path = _sub(info.source, 2, -8)

    return path .. "ipipfree.ipdb"

end


local function _uint16(a, b)
    if not a or not b then
        return nil
    end

    local u = lshift(a, 8) + b
    if u < 0 then
        u = u + math.pow(2, 16)
    end

    return u
end


local function _uint32(a, b, c, d)
    if not a or not b or not c or not d then
        return nil
    end

    local u = lshift(a, 24) + lshift(b, 16) + lshift(c, 8) + d
    if u < 0 then
        u = u + math.pow(2, 32)
    end

    return u
end


local function read_node(data, node, index)
    local off = node * 8 + index * 4 + 1
    return _uint32(_byte(data, off, off+3))
end


local function check_addr_type(addr)
    local m, err = _match(addr, ipv4_pattern)
    if m then
        return IPV4
    end

    -- TODO: support IPV6
    return IPV6
end

-- 读取数据库文件
local function read_date(filepath)
    if not filepath then
        return nil, INVALID_FILE_PATH
    end

    local  file, err = io.open(filepath, "rb")
    if not file then return nil, err end

    local data, err = file:read("*all"); file:close()
    return data, err
end

-- 解析数据库
local function parse_data(data)
-- @data    : string    //数据库内容
-- @return  : @DBInfo   //数据库信息

    local meta_length = _uint32(_byte(data, 1, 4))
    if not meta_length then return nil, INVALID_DB_FORMAT end

    local text = _sub(data, 5, 5+meta_length)

    local obj = cjson.decode(text)
    if type(obj) ~= "table" then return nil, INVALID_DB_FORMAT end

    local meta = {
        build       = 1562137969,
        ip_version  = 1,
        languages   = { CN = 0 },
        node_count  = 451190,
        total_size  = 3649744,
        fields      = { "country_name","region_name","city_name" },
    }

    for k, v in pairs(obj) do
        meta[k] = v
    end

    local v4offset = 0
    local content_data = data:sub(5+meta_length)
    for i=0, 95, 1 do
        if v4offset >= meta.node_count then
            break
        end

        if i >= 80 then
            v4offset = read_node(content_data, v4offset, 1)
        else
            v4offset = read_node(content_data, v4offset, 0)
        end
    end

    return { meta = meta, data = content_data, v4offset = v4offset }

end

_T.DBInfo = { "//数据库定义",
    meta = { "//数据库元信息",
        build       = "number   //打包时间",
        ip_version  = "number   //IP版本",
        languages   = { "//语言信息",
                CN  = "number   //中文信息位置"
            },
        node_count  = "number   //节点数量",
        total_size  = "number   //IP总数量",
        fields      = "string[] //字段列表",
    },
    data     = "string  //数据库内容",
    v4offset = "number  //IPV4偏移地址"
}

-- 加载指定路径的数据库文件并创建实例
function _M.new(filepath)
-- @@ 这是构造函数
-- @filepath    : string    //数据库文件路径

    -- 默认使用同目录下的 ipipfree.ipdb
    filepath = filepath or get_ipipfree_ipdb()

    local  data, err = read_date(filepath)
    if not data then return nil, err end

    local  db, err = parse_data(data)
    if not db then return nil, err end

    setmetatable(db, mt)
    return db
end

-- 解析IP信息
function _M:resolve(node)
-- @node    : number    //IP信息位置
-- @return  : string    //IP信息字符串

    local resolved = node + self.meta.node_count * 7
    if resolved >= self.meta.total_size then
        return nil, DATABASE_ERR
    end

    local size = _uint16(_byte(self.data, resolved+1, resolved+2))
    if resolved + 2 + size > (#self.data) then
        return nil, DATABASE_ERR
    end

    return _sub(self.data, resolved+2+1, resolved+2+size)
end

-- 查找指定IP在数据库中的节点位置
function _M:search(ip, bitcount)
-- @ip          : string // IP地址
-- @bitcount    : number // IP地址位数
-- @return      : number // 节点位置

    local node = bitcount == 32 and self.v4offset or 0

    for i = 0, bitcount-1, 1 do
        if node > self.meta.node_count then
            break
        end

        local temp = ip[rshift(i, 3)+1]
        node = read_node(self.data, node, band(rshift(band(0xFF, temp), (7 - i % 8)), 1))
    end

    if node > self.meta.node_count then
        return node
    end

    return nil,  INVALID_DB_FORMAT

end

-- 查找全部语言的IP信息
function _M:find_all(addr)
-- @add     : string    //IP地址
-- @return  : string[]  //IP信息字符串数组

    local ip_type = check_addr_type(addr)

    local node, err

    if ip_type == IPV4 then
        local ip, err  = _split(addr, "\\.")
        if not ip then return nil, err end
        node, err = self:search(ip, 32)
    elseif ip_type == IPV6 then
        node, err = self:search(addr, 128)
    end

    if not node then return nil, err end

    local content, err = self:resolve(node)
    if not content then
        return nil, err
    end

    local res, err = _split(content, "\t")
    if not res then return nil, err end

    return res
end

_T.IpInfo = { "//IP地址信息",
    country_name    = "//国家",
    region_name     = "//省份",
    city_name       = "//城市",
}

-- 查找指定语言的IP信息
function _M:find(addr, language)
-- @addr        : string    //IP地址
-- @language    : string    //语言(默认CN)
-- @return      : @IpInfo   //IP信息

    language = language or "CN"

    local off = self.meta.languages[language]
    if not off then return nil, LANGUAGE_ERR end

    local body, err = self:find_all(addr)
    if not body then
        return nil, err
    end

    if off + #(self.meta.fields) > #body then
        return nil, INVALID_DB_FORMAT
    end

    local res = {
        country_name    = "",
        region_name     = "",
        city_name       = "",
    }

    for k, v in ipairs(self.meta.fields) do
        res[v] = body[k]
    end

    return res

end

return _M
