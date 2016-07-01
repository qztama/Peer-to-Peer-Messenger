p2pim: main.cpp host.cpp packets.cpp EncryptionLibrary.cpp
	g++ -o p2pim main.cpp host.cpp packets.cpp EncryptionLibrary.cpp

clean:
	rm *.o temp