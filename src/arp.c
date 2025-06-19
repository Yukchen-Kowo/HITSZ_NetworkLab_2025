#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    // Step1 ：调用buf_init()对txbuf进行初始化。
    buf_init(&txbuf, sizeof(arp_pkt_t));

    //Step2 ：填写ARP报头
    arp_pkt_t __arp_pkt = arp_init_pkt;
    __arp_pkt.hw_type16 = swap16(ARP_HW_ETHER);
    __arp_pkt.pro_type16 = swap16(NET_PROTOCOL_IP);
    __arp_pkt.hw_len = NET_MAC_LEN;
    __arp_pkt.pro_len = NET_IP_LEN;
    //Step3 ：ARP操作类型为ARP_REQUEST，注意大小端转换。
    __arp_pkt.opcode16 = swap16(ARP_REQUEST);
    memcpy(__arp_pkt.sender_mac,net_if_mac,NET_MAC_LEN);
    memcpy(__arp_pkt.sender_ip,net_if_ip,NET_IP_LEN);
    memcpy(__arp_pkt.target_ip, target_ip, NET_IP_LEN);
    memcpy(txbuf.data, &__arp_pkt, sizeof(arp_pkt_t));

    //Step4 ：调用ethernet_out函数将ARP报文发送出去。注意：ARP announcement或ARP请求报文都是广播报文，
    //        其目标MAC地址应该是广播地址：FF-FF-FF-FF-FF-FF。
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    //Step1 ：首先调用buf_init()来初始化txbuf。
    buf_init(&txbuf, sizeof(arp_pkt_t));

    //Step2 ：接着，填写ARP报头首部。
    arp_pkt_t __arp_pkt = arp_init_pkt;
    __arp_pkt.hw_type16 = swap16(ARP_HW_ETHER);
    __arp_pkt.pro_type16 = swap16(NET_PROTOCOL_IP);
    __arp_pkt.hw_len = NET_MAC_LEN;
    __arp_pkt.pro_len = NET_IP_LEN;
    __arp_pkt.opcode16 = swap16(ARP_REPLY);
    memcpy(__arp_pkt.sender_ip,net_if_ip,NET_IP_LEN);
    memcpy(__arp_pkt.target_ip, target_ip, NET_IP_LEN);
    memcpy(__arp_pkt.sender_mac,net_if_mac,NET_MAC_LEN);
    memcpy(__arp_pkt.target_mac, target_mac, NET_MAC_LEN);
    memcpy(txbuf.data, &__arp_pkt, sizeof(__arp_pkt));

    //Step3 ：调用ethernet_out()函数将填充好的ARP报文发送出去。
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    //Step1 ：首先判断数据长度，如果数据长度小于ARP头部长度，则认为数据包不完整，丢弃不处理。
    //Step2 ：接着，做报头检查，查看报文是否完整，检测内容包括：ARP报头的硬件类型、上层协议类型、MAC硬件地址长度、IP协议地址长度、
    //        操作类型，检测该报头是否符合协议规定。
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;

    if (
        buf->len < sizeof(arp_pkt_t) || 
        arp_pkt->hw_type16 != swap16(ARP_HW_ETHER) ||
        arp_pkt->pro_type16 != swap16(NET_PROTOCOL_IP) ||
        arp_pkt->hw_len != NET_MAC_LEN ||
        arp_pkt->pro_len != NET_IP_LEN ||
        (arp_pkt->opcode16 != swap16(ARP_REQUEST) &&
        arp_pkt->opcode16 != swap16(ARP_REPLY))
    )   
    return;
    
    //Step3 ：调用map_set()函数更新ARP表项。
    map_set(&arp_table, arp_pkt->sender_ip, src_mac);

    //Step4 ：调用map_get()函数查看该接收报文的IP地址是否有对应的arp_buf缓存。
    buf_t *__arp_buf = (buf_t *)map_get(&arp_buf, arp_pkt->sender_ip);
    if (__arp_buf != NULL) {
        // ethernet_out(__arp_buf, arp_pkt->sender_mac, arp_pkt->pro_type16);
        ethernet_out(__arp_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt->sender_ip);
        return;
    }
    if (arp_pkt->opcode16 == swap16(ARP_REQUEST) &&
        memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
        arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    // 调用map_get()函数，根据IP地址来查找ARP表(arp_table)
    uint8_t *target_mac = (uint8_t *) map_get(&arp_table, ip);

    if (target_mac != NULL) {
        ethernet_out(buf, target_mac, NET_PROTOCOL_IP);
        return;
    }

    if (map_get(&arp_buf, ip) == NULL) {
        map_set(&arp_buf, ip, buf);
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}