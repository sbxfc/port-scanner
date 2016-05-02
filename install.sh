mkdir bin
gcc src/main.c -o bin/port_scan
cp bin/port_scan /usr/bin/
rm -r bin
