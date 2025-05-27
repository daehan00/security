CXX = g++
CXXFLAGS = -Wall -O2 -std=c++17

all: echo-server echo-client

echo-server: echo-server.cpp myQueue.cpp
	$(CXX) $(CXXFLAGS) -o echo-server echo-server.cpp myQueue.cpp -lpthread

echo-client: echo-client.cpp
	$(CXX) $(CXXFLAGS) -o echo-client echo-client.cpp

clean:
	rm -f echo-server echo-client
