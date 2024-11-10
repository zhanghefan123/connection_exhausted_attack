//
// Created by zhf on 2024/11/7.
//

#ifndef TCP_OFF_PATH_COMMON_H
#define TCP_OFF_PATH_COMMON_H

#include <random>
#include <tins/tins.h>

typedef std::chrono::high_resolution_clock::time_point Clock;
typedef Tins::HWAddress<6> MACAddress;

class CommandArgs {
public:
    char *interfaceName{};
    char *serverIp{};
    int serverPort{};
    int attackDuration{};
    CommandArgs();
    CommandArgs(char* interfaceName, char* serverIp, int serverPort, int attackDuration);
};

class GlobalArgs {
public:
    CommandArgs commandArgs;
    Tins::PacketSender packetSender;
    Tins::NetworkInterface interface;
    GlobalArgs();
    void initialize(CommandArgs commandArgs);
};

extern GlobalArgs globalArgs;



#endif //TCP_OFF_PATH_COMMON_H
