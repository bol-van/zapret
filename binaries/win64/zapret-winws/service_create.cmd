set ARGS=--wf-l3=ipv4,ipv6 --wf-tcp=80,443 --dpi-desync=fake,split --dpi-desync-ttl=7 --dpi-desync-fooling=md5sig
call :srvinst winws1
rem set ARGS=--wf-l3=ipv4,ipv6 --wf-udp=443 --dpi-desync=fake 
rem call :srvinst winws2
goto :eof

:srvinst
net stop %1
sc delete %1
sc create %1 binPath= "\"%~dp0winws.exe\" %ARGS%" DisplayName= "zapret DPI bypass : %1" start= auto
sc description %1 "zapret DPI bypass software"
sc start %1
