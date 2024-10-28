Standalone version in zapret-winws folder !!
From this folder winws can be started only from cygwin shell.

Cygwin refuses to start winws if a copy of cygwin1.dll is present !

How to get win7 and winws compatible version of cygwin :

curl -O https://www.cygwin.com/setup-x86_64.exe
setup-x86_64.exe --allow-unsupported-windows --no-verify --site http://ctm.crouchingtigerhiddenfruitbat.org/pub/cygwin/circa/64bit/2024/01/30/231215
