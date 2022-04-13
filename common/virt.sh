get_virt()
{
	local vm s v UNAME
	UNAME=$(uname)
	case "$UNAME" in
		Linux)
			if exists systemd-detect-virt; then
				vm=$(systemd-detect-virt --vm)
			elif [ -f /sys/class/dmi/id/product_name ]; then
				read s </sys/class/dmi/id/product_name
				for v in KVM QEMU VMware VMW VirtualBox Xen Bochs Parallels BHYVE Hyper-V; do
					case "$s" in
						"$v"*)
						vm=$v
						break
		    			;;
					esac
				done
			fi
			;;
	esac
	echo "$vm" | awk '{print tolower($0)}'
}
check_virt()
{
	echo \* checking virtualization
	local vm=$(get_virt)
	if [ -n "$vm" ]; then
		if [ "$vm" = "none" ]; then
			echo running on bare metal
		else
			echo "!!! WARNING. $vm virtualization detected !!!"
			echo '!!! WARNING. vmware and virtualbox are known to break most of the DPI bypass techniques when network is NATed using internal hypervisor NAT !!!'
			echo '!!! WARNING. if this is your case make sure you are bridged not NATed !!!'
		fi
	else
		echo cannot detect
	fi
}
