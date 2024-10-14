start "zapret: http,https,quic" /min "%~dp0winws.exe" ^
--wf-tcp=80,443 --wf-udp=443 ^
--filter-udp=443 --hostlist="%~dp0list-youtube.txt" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic="%~dp0quic_initial_www_google_com.bin" --new ^
--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=11 --new ^
--filter-tcp=80 --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --hostlist-auto="%~dp0autohostlist.txt" --new ^
--filter-tcp=443 --hostlist="%~dp0list-youtube.txt" --dpi-desync=fake,split2 --dpi-desync-repeats=11 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls="%~dp0tls_clienthello_www_google_com.bin" --new ^
--dpi-desync=fake,disorder2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --hostlist-auto="%~dp0autohostlist.txt"
