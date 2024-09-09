CFLAGS=-O3 -march=native -mtune=native -ggdb
CXXFLAGS=$(CFLAGS)
RELIC_ROOT = ../..

INC_DIR = inc
SRC_DIR = src
BULLETPROOF_DIR = bulletproof
# BUILD_DIR = build
TARGET=main

# 获取src目录下的所有.c文件
SRCS = $(wildcard $(SRC_DIR)/*.c) 
# 对应的.o文件
OBJS = $(SRCS:.c=.o)
# 头文件依赖
DEPS = $(wildcard $(INC_DIR)/*.h)

all: libbullet $(TARGET)
	@$(MAKE) clean_objects

# 构建libbullet.a
.PHONY: libbullet
libbullet:
	$(MAKE) -C $(BULLETPROOF_DIR) clean
	$(MAKE) -C $(BULLETPROOF_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 通用规则来编译所有.c文件到.o文件
%.o: %.c $(DEPS)
	gcc $(CFLAGS) -c $< -o $@ -I $(RELIC_ROOT)/include -I $(INC_DIR) -I target-gmp/include

$(TARGET): $(OBJS) | $(BUILD_DIR)
	gcc $(CFLAGS) -o $@ $^ $(BULLETPROOF_DIR)/libbullet.a -lstdc++ -lssl -lcrypto target-gmp/lib/librelic_s.a -lgmp -lm

lib:
	mkdir -p target-gmp
	cd target-gmp;  ../scheme2.sh $(RELIC_ROOT)/../; make

clean:
	rm -rf target-gmp *.o $(BUILD_DIR)

# 清理生成的.o文件
clean_objects:
	rm -f $(SRC_DIR)/*.o
