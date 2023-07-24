dexparser: dexparser.o dexhelper.o
	g++ $(CFLAGS) -o dexparser dexparser.o dexhelper.o

dexparser.o: dexparser.cpp
	g++ $(CFLAGS) -o dexparser.o -c dexparser.cpp

dexhelper.o: dexhelper.cpp
	g++ $(CFLAGS) -o dexhelper.o -c dexhelper.cpp

clean:
	rm dexhelper.o dexparser.o dexparser