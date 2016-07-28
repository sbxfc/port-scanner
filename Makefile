
VPATH = src

scanner : main.c
	gcc src/main.c -o scanner

clean:
	-rm scanner 
