start "zapret: http,https,autohostlist" "%~dp0winws.exe" --wf-tcp=80,443 --dpi-desync=fake,disorder2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --hostlist-auto="%~dp0autohostlist.txt"
timeout /t 1
start "zapret: quic,autohostlist" "%~dp0winws.exe" --wf-udp=443 --dpi-desync=fake --dpi-desync-repeats=10 --hostlist-auto="%~dp0autohostlist.txt"