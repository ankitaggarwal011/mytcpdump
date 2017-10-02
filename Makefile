all:
	g++ mydump.cpp -std=c++0x -lpcap -o mydump
clean:
	rm -rf mydump
run:
	./mydump