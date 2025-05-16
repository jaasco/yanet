CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -I../../../

TARGET = sni_bench
SRC = parse_tls_sni.cpp  

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
