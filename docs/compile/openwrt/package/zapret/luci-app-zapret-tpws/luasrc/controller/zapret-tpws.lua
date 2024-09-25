module("luci.controller.zapret-tpws", package.seeall)
function index()
	if nixio.fs.access("/etc/config/zapret") then
		entry({"admin", "services", "zapret-tpws"}, cbi("zapret-tpws"), _("TPWS Configuration")).acl_depends = { "luci-app-zapret-tpws" }
	end
end
