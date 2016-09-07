
VPATH = src

scanner : main.c
	gcc src/main.c -o scan

clean:
	-rm scan
