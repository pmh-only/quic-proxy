CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread $(CPPFLAGS)
INCLUDES = -I/usr/include/openssl -I/usr/include $(if $(shell pkg-config --exists openssl),$(shell pkg-config --cflags openssl))
LIBS = -lssl -lcrypto -lz -lbrotlienc -lzstd -lnghttp2 -lnghttp3 -lpthread $(LDFLAGS)

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
	docker build -t $(TARGET):v1.2.2 .

docker-http3:
	echo "Building Docker image with HTTP/3 QUIC and advanced TLS support..."
	docker build -t $(TARGET):v1.2.2-http3 .
	echo "✅ Docker build with HTTP/3 and advanced TLS completed"

docker-run:
	docker run -d \
		--name $(TARGET) \
		-p 80:80 \
		-p 443:443 \
		-p 443:443/udp \
		-e BACKEND_HOST=127.0.0.1 \
		-e BACKEND_PORT=8080 \
		-e HTTP3_ENABLED=true \
		-e ADVANCED_TLS_ENABLED=true \
		-e WAF_ENABLED=true \
		-v /etc/ssl:/etc/ssl:ro \
		$(TARGET):v1.2.2

docker-run-http3:
	docker run -d \
		--name $(TARGET)-http3 \
		-p 80:80 \
		-p 443:443 \
		-p 443:443/udp \
		-e BACKEND_HOST=127.0.0.1 \
		-e BACKEND_PORT=8080 \
		-e HTTP3_ENABLED=true \
		-e QUIC_0RTT_ENABLED=true \
		-e ADVANCED_TLS_ENABLED=true \
		-e TLS_EARLY_DATA_ENABLED=true \
		-e WAF_ENABLED=true \
		-v /etc/ssl:/etc/ssl:ro \
		$(TARGET):v1.2.2-http3

# Development targets
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

# HTTP/3 QUIC and advanced TLS enabled build
http3: CPPFLAGS += -DENABLE_HTTP3_QUIC -DENABLE_ADVANCED_TLS
http3: CXXFLAGS += -DENABLE_HTTP3_QUIC -DENABLE_ADVANCED_TLS
http3: $(TARGET)

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
	docker build -t coraza-waf:v1.2.2 waf/

waf-clean:
	rm -f waf-service
	cd waf && go clean

# Combined build target
all-services: $(TARGET) waf-service

# Dependency tracking
depend:
	$(CXX) -MM $(SOURCES) > .depend

-include .depend
