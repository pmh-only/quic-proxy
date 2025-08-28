CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
INCLUDES = -I/usr/include/openssl
LIBS = -lssl -lcrypto -lz -lbrotlienc -lzstd -lpthread

TARGET = quic-proxy
SRCDIR = .
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

.PHONY: all clean install uninstall docker waf-service waf-docker

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	install -D $(TARGET) /usr/local/bin/$(TARGET)
	install -D -m 644 systemd/$(TARGET).service /etc/systemd/system/
	systemctl daemon-reload

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	systemctl stop $(TARGET) || true
	systemctl disable $(TARGET) || true
	rm -f /etc/systemd/system/$(TARGET).service
	systemctl daemon-reload

docker:
	docker build -t $(TARGET):latest .

docker-run:
	docker run -d \
		--name $(TARGET) \
		-p 80:80 \
		-p 443:443 \
		-e BACKEND_HOST=127.0.0.1 \
		-e BACKEND_PORT=8080 \
		-v /etc/ssl:/etc/ssl:ro \
		$(TARGET):latest

# Development targets
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

test: $(TARGET)
	./test/run_tests.sh

format:
	find . -name "*.cpp" -o -name "*.h" | xargs clang-format -i

lint:
	find . -name "*.cpp" -o -name "*.h" | xargs cppcheck --enable=all --std=c++17

# WAF Service targets
waf-service:
	cd waf && go mod tidy && go build -o ../waf-service .

waf-docker:
	docker build -t coraza-waf:latest waf/

waf-clean:
	rm -f waf-service
	cd waf && go clean

# Combined build target
all-services: $(TARGET) waf-service

# Dependency tracking
depend:
	$(CXX) -MM $(SOURCES) > .depend

-include .depend