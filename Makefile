# 变量定义
CC = gcc
CFLAGS = -Wall -Wextra -I./include  -std=gnu99
LDFLAGS = -lm -lcrypto -lrpm

# 源文件和对象文件
SRC = main.c include/cJSON.c
OBJ = $(SRC:.c=.o)

# 输出目标
TARGET = program

# 默认目标
all: $(TARGET)

# 链接目标文件生成可执行文件
$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

# 编译源文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理生成的文件
clean:
	rm -f $(OBJ) $(TARGET)

# 伪目标
.PHONY: all clean
