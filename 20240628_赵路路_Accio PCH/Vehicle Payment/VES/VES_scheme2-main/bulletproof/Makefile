# 设置编译器和编译选项
CC = g++
CFLAGS = -Wall -std=c++11
LDFLAGS = -lssl -lcrypto -lm

# 获取所有的源文件和目标文件
SRCS := $(wildcard *.cpp)
OBJS := $(SRCS:.cpp=.o)

# 定义最终生成的静态链接库名称
LIBNAME = libbullet.a

# 定义编译目标
all: $(LIBNAME)

# 生成静态链接库
$(LIBNAME): $(OBJS)
	ar rcs $@ $^
	rm -rf *.o

# 编译每个源文件为目标文件
%.o: %.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

# 在每次make结束时清除生成的.o文件
.PHONY: clean
clean:
	rm -rf *.o *.a
