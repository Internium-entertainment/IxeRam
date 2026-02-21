CXX = g++
CXXFLAGS = -std=c++17 -Iinclude -Wall -Wextra
LDFLAGS = -lncursesw

SRCS = src/main.cpp src/MemoryEngine.cpp src/Scanner.cpp src/TUI.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = memdebug

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
