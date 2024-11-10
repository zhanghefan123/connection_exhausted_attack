//
// Created by zhf on 2024/11/7.
//
#include "common.h"

CommandArgs::CommandArgs() = default;

CommandArgs::CommandArgs(char* interfaceName, char* serverIp, int serverPort, int attackDuration) {
    this->interfaceName = interfaceName;
    this->serverIp = serverIp;
    this->serverPort = serverPort;
    this->attackDuration = attackDuration;
}

GlobalArgs::GlobalArgs() = default;

void GlobalArgs::initialize(CommandArgs commandArgsTmp){
    this->commandArgs = commandArgsTmp;
    this->packetSender = Tins::PacketSender(this->commandArgs.interfaceName);
    this->interface = Tins::NetworkInterface(this->commandArgs.interfaceName);
}
