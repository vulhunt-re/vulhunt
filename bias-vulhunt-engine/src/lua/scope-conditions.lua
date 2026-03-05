-- caller api for scope.calls

caller = { }

function caller:calls (v)
  if __current_function == nil then
    return false
  end
  return __current_function:calls (v)
end

function caller:has_call (v)
  if __current_function == nil then
    return false
  end
  return __current_function:has_call (v)
end

function caller:has_calls (vs)
  if __current_function == nil then
    return false
  end
  if type (vs) == "table" then
    for _, v in ipairs (vs) do
      if not __current_function:has_call (v) then
        return false
      end
    end
    return true
  else
    return __current_function:has_call (vs)
  end
end

function caller:named (v)
  if __current_function == nil then
    return false
  end
  return __current_function:named (v)
end
