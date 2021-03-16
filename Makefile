CXXFLAGS += -std=c++17 -O3 -march=native -Wall -Wextra
BINS = traceroute

all: $(BINS)

%: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	$(RM) $(BINS)
