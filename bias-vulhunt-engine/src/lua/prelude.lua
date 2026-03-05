--
-- prelude.lua
--
-- Provides utility functions to ease checker development
--

-- construction functions for scopes

ffi = require "ffi"

scope = {}

function scope:project(v)
  if type(v) ~= "table" then
    error "scope:project: invalid scoping rule"
  end

  local with = v["with"]
  local where = v["where"]

  if type(with) ~= "string" then
    error "scope:project: invalid scoping rule -- `with` clause should be a function"
  end

  if where ~= nil and type(where) ~= "table" then
    error "scope:project: invalid scoping rule -- `where` clause should be a table"
  end

  return {
    kind = "project",
    with = with,
    where = where,
  }
end

function scope:functions(v)
  if type(v) ~= "table" then
    error "scope:functions: invalid scoping rule"
  end

  local with = v["with"]
  local named = v["named"]
  local target = v["target"]
  -- local where = v["where"]

  if type(with) ~= "string" then
    error "scope:functions: invalid scoping rule -- `with` clause should be a function"
  end

  if named ~= nil and target ~= nil then
    error "scope:functions: cannot specify both `named` and `target`"
  end

  if named ~= nil and (type(named) ~= "string" or string.len(named) == 0) then
    error "scope:functions: invalid scoping rule -- `named` should be a non-empty string"
  end

  if target ~= nil and type(target) ~= "table" and (type(target) ~= "string" or string.len(target) == 0) then
    error "scope:functions: invalid scoping rule -- `target` should be a table or a non-empty string"
  end

  -- if where ~= nil and type(where) ~= "table" then
  --  error "scope:functions: invalid scoping rule -- `where` clause should be a table"
  -- end

  return {
    kind = "functions",
    with = with,
    named = named,
    target = target,
    -- where = where,
  }
end

function scope:calls(v)
  if type(v) ~= "table" then
    error "scope:functions: invalid scoping rule"
  end

  local to = v["to"]
  local with = v["with"]
  local where = v["where"]
  local using = v["using"]

  if type(to) ~= "table" and (type(to) ~= "string" or string.len(to) == 0) then
    error "scope:calls: invalid scoping rule -- `to` should be a table or a non-empty string"
  end

  if type(with) ~= "string" then
    error "scope:calls: invalid scoping rule -- `with` clause should be a function"
  end

  -- NOTE: where will be rewritten to be a string so this is just some sanity
  if where ~= nil and type(where) ~= "string" then
    error "scope:calls: invalid scoping rule -- `where` clause should be an expression"
  end

  if using ~= nil and type(using) ~= "table" then
    error "scope:calls: invalid scoping rule -- `using` clause should be a table"
  end

  return {
    kind = "calls",
    to = to,
    with = with,
    where = where,
    using = using,
  }
end

-- constructors for variable specifications

var = {}
_ = { name = nil }

function var:named(name)
  if name == nil or string.len(name) == 0 then
    error "var:named: missing or invalid 'name'"
  end

  return { name = name }
end

function var:sanitised()
  return { sanitiser = true }
end

var.sanitized = var.sanitised

-- constructors for results

result = {}

function result:new(severity, kind, details)
  local v = details or {}

  if type(severity) ~= "string" then
    error "result: invalid severity"
  end

  if type(v) ~= "table" then
    error "result: invalid result details"
  end

  v["kind"] = kind
  v["severity"] = severity

  return v
end

function result:vulnerability(severity, details)
  return result:new(severity, "vulnerability", details)
end

function result:none(v)
  return result:vulnerability("none", v)
end

function result:info(v)
  return result:none(v)
end

function result:unspecified(v)
  return result:none(v)
end

function result:low(v)
  return result:vulnerability("low", v)
end

function result:medium(v)
  return result:vulnerability("medium", v)
end

function result:high(v)
  return result:vulnerability("high", v)
end

function result:critical(v)
  return result:vulnerability("critical", v)
end

function result:patch(v)
  return result:new("none", "patch", v)
end

function result:malware(v)
  return result:new("high", "malware", v)
end

-- constructor for result annotations
annotate = { fidx = 1000 }

function annotate:at(v)
  if type(v) ~= "table" then
    error "annotate: invalid annotation"
  end

  local location = v["location"]
  local message = v["message"]

  if location == nil then
    error "annotate: invalid annotation -- missing location"
  end

  if message == nil or string.len(message) == 0 then
    error "annotate: invalid annotation -- missing message"
  end

  return {
    kind = "at",
    location = location,
    message = message,
  }
end

function annotate:prototype(v)
  -- v can be a table containing an index number, an optional location,
  -- and a prototype string; or it can be only prototype string;
  -- if location is not specified, the current function will be annotated;
  -- if index is not specified, the global counter will be used as an index

  if type(v) ~= "table" and (type(v) ~= "string" or string.len(v) == 0) then
    error("annotate: invalid annotation")
  end

  local prototype, location, index

  if type(v) == "table" then
    index = v["index"]
    if index ~= nil and type(index) ~= "number" then
      error("annotate: invalid index")
    end

    prototype = v["prototype"]
    if type(prototype) ~= "string" or string.len(prototype) == 0 then
      error("annotate: invalid prototype")
    end

    location = v["location"]
    if location ~= nil and type(location) ~= "userdata" then
      error("annotate: invalid location")
    end
  else
    prototype = v
  end

  if index == nil then
    index = annotate.fidx
    annotate.fidx = annotate.fidx + 1
  end

  return {
    kind = "prototype",
    prototype = prototype,
    location = location,
    index = index
  }
end

function annotate:assignment(v)
  if type(v) ~= "table" then
    error "annotate: invalid annotation"
  end

  v["position"] = "output"
  v["index"] = 0

  return annotate:variable(v)
end

function annotate:global(v)
  if type(v) ~= "table" then
    error "annotate: invalid annotation"
  end

  v["position"] = "global"
  v["index"] = 0

  return annotate:variable(v)
end

function annotate:variable(v)
  if type(v) ~= "table" then
    error "annotate: invalid annotation"
  end

  local position = v["position"]
  local index = v["index"]
  local declaration = v["declaration"]
  local location = v["location"]

  if type(position) ~= "string" or (position ~= "input" and position ~= "output" and position ~= "global") then
    error "annotate: invalid annotation -- position should be `global`, `input`, or `output`"
  end

  if index == nil or type(index) ~= "number" or index < 0 then
    error "annotate: invalid annotation -- index should be a positive integer"
  end

  if declaration == nil or string.len(declaration) == 0 then
    error "annotate: invalid annotation -- missing declaration"
  end

  if location == nil then
    error "annotate: invalid annotation -- missing location"
  end

  return {
    kind = "variable",
    location = location,
    position = position,
    index = index,
    declaration = declaration,
  }
end

function annotate:range(v)
  if type(v) ~= "table" then
    error "annotate: invalid annotation"
  end

  local from = v["from"]
  local to = v["to"]
  local message = v["message"]

  if from == nil or to == nil then
    error "annotate: invalid annotation -- missing or incomplete range"
  end

  if message == nil or string.len(message) == 0 then
    error "annotate: invalid annotation -- missing message"
  end

  return {
    kind = "range",
    from = from,
    to = to,
    message = message,
  }
end

function annotate:operand(v)
  if type(v) ~= "table" then
    error "annotate: invalid annotation"
  end

  -- we expect it to be a OperandInfo
  local at = v["at"]
  local value = v["operand"]
  local message = v["message"]

  if at == nil then
    error "annotate: invalid annotation -- missing location"
  end

  if type(value) ~= "userdata" then
    error "annotate: invalid annotation -- invalid operand"
  end

  local annotation = value.annotation
  local origin = value.origin

  if message == nil or string.len(message) == 0 then
    error "annotate: invalid annotation -- missing message"
  end

  return {
    kind = "operand",
    location = at,
    annotation = annotation,
    origin = origin,
    message = message,
  }
end

cvss = {}

function cvss:check_score(score)
  if score == nil or type(score) ~= "string" or string.len(score) == 0 then
    error "cvss: invalid score"
  end

  -- check range
  local value = tonumber(score)
  if value == nil or value < 0.0 or value > 10.0 then
    error "cvss: invalid score range"
  end

  return score
end

function cvss:check_vector(vector)
  if vector == nil or type(vector) ~= "string" or string.len(vector) == 0 then
    error "cvss: invalid vector"
  end

  return vector
end

function cvss:v2(v)
  if type(v) ~= "table" then
    error "cvss: invalid cvss data"
  end

  local version = "2.0"
  local base = v["base"]
  local exploitability = v["exploitability"]
  local impact = v["impact"]
  local vector = v["vector"]

  return {
    v2 = {
      version = version,
      base_score = cvss:check_score(base),
      exploitability_score = cvss:check_score(exploitability),
      impact_score = cvss:check_score(impact),
      vector = cvss:check_vector(vector),
    }
  }
end

function cvss:v3(v)
  if type(v) ~= "table" then
    error "cvss: invalid cvss data"
  end

  local version = "3.0"
  local base = v["base"]
  local exploitability = v["exploitability"]
  local impact = v["impact"]
  local vector = v["vector"]

  return {
    v3 = {
      version = version,
      base_score = cvss:check_score(base),
      exploitability_score = cvss:check_score(exploitability),
      impact_score = cvss:check_score(impact),
      vector = cvss:check_vector(vector),
    }
  }
end

function cvss:v3_1(v)
  if type(v) ~= "table" then
    error "cvss: invalid cvss data"
  end

  local version = "3.1"
  local base = v["base"]
  local exploitability = v["exploitability"]
  local impact = v["impact"]
  local vector = v["vector"]

  return {
    v3 = {
      version = version,
      base_score = cvss:check_score(base),
      exploitability_score = cvss:check_score(exploitability),
      impact_score = cvss:check_score(impact),
      vector = cvss:check_vector(vector),
    }
  }
end

function cvss:v4(v)
  if type(v) ~= "table" then
    error "cvss: invalid cvss data"
  end

  local version = "4.0"
  local base = v["base"]
  local exploitability = v["exploitability"]
  local impact = v["impact"]
  local vector = v["vector"]

  return {
    v4 = {
      version = version,
      base_score = cvss:check_score(base),
      exploitability_score = cvss:check_score(exploitability),
      impact_score = cvss:check_score(impact),
      vector = cvss:check_vector(vector),
    }
  }
end

-- utils

container = {}

function container.empty(self)
  for _, _ in pairs(self) do
    return false
  end
  return true
end

function printf(fmt, ...)
  return print(string.format(fmt, ...))
end

-- validators

validate = {
  -- constants
  anywhere = { anchor = "anywhere" }
}

function validate:all(v)
  if type(v) ~= "table" then
    error "validate: invalid validator"
  end

  return {
    op = "all",
    args = v,
  }
end

function validate:any(v)
  if type(v) ~= "table" then
    error "validate: invalid validator"
  end

  return {
    op = "any",
    args = v,
  }
end

-- Unfortunately, `not` is a keyword in Lua and we can't use it as a method
-- name, that said, we can probably use the preprocessor to rewrite `validate:not`
-- to `validate:not_`.
function validate:not_(v)
  if type(v) ~= "table" then
    error "validate: invalid validator"
  end

  return {
    op = "not",
    args = v,
  }
end

function validate:contains(v)
  if type(v) == "string" then
    return {
      op = "contains",
      args = { pattern = v },
    }
  end

  if type(v) ~= "table" then
    error "validate: invalid validator"
  end

  local pattern = v["pattern"]
  local where = v["where"]
  local kind = v["kind"]

  if pattern == nil or type(pattern) ~= "string" then
    error "validate: invalid validator -- missing or invalid `pattern`"
  end

  if where ~= nil and type(where) ~= "table" then
    error "validate: invalid validator -- missing or invalid `where`"
  end

  if kind ~= nil and type(kind) ~= "string" then
    error "validate: invalid validator -- missing or invalid `kind`"
  end

  return {
    op = "contains",
    args = {
      pattern = pattern,
      where = where or validate.anywhere,
      kind = kind or "bytes",
    }
  }
end

function validate:at(v)
  if type(v) ~= "number" then
    error "validate: invalid validator -- at should be an integer"
  end

  if v < 0 then
    error "validate: invalid validator -- at should be a non-negative integer"
  end

  return {
    anchor = "at",
    args = v,
  }
end

function validate:from(v)
  if type(v) ~= "number" then
    error "validate: invalid validator -- from should be an integer"
  end

  if v < 0 then
    error "validate: invalid validator -- from should be a non-negative integer"
  end

  return {
    anchor = "from",
    args = v,
  }
end
