m = Map("zapret", translate("TPWS Proxy Settings"))
c = m:section(NamedSection, "tpws", "zapret", translate("Configuration"))
opt = c:option(Value, "opts", translate("TPWS Options"))
opt.placeholder = "--split-pos=2"
function opt.validate(self, value)
    local words = {}
    for word in value:gmatch("%S+") do
        table.insert(words, word)
    end
    for _, word in ipairs(words) do
        if word:sub(1, 2) ~= "--" then
            return nil, translate("The field value \"TPWS Options\" has incorrect format")
        end
    end
    return value
end
b = c:option(Flag, "block_quic", "Block QUIC", translate("Block QUIC protocol to come outside"))
lp = c:option(Value, "port", translate("Listen Port"))
lp.datatype = "port"
lp.placeholder = "8088"
fp = c:option(Value, "forward_ports", translate("Ports, forwarded to proxy"))
fp.datatype = "list(neg(portrange))"
fp.placeholder = "80 443"
return m
