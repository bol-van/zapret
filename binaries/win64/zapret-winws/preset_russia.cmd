start "zapret: http,https" "%~dp0winws.exe" --wf-tcp=80,443 --dpi-desync=fake,disorder2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig
timeout /t 1
start "zapret: quic" "%~dp0winws.exe" --wf-udp=443 --dpi-desync=fake --dpi-desync-repeats=11