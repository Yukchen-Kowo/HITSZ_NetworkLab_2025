#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // TO-DO
    //Step1 ：调用buf_init()来初始化txbuf，然后封装报头和数据，数据部分可以拷贝来自接收的回显请求报文中的数据。
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    //Step2 ：填写校验和，ICMP的校验和和IP协议校验和算法是一样的。
    icmp_hdr_t *req_icmp_hdr = (icmp_hdr_t *)req_buf->data;
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t*)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    icmp_hdr->code = 0;
    icmp_hdr->checksum16 = 0;
    icmp_hdr->id16 = req_icmp_hdr->id16;
    icmp_hdr->seq16 = req_icmp_hdr->seq16;
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    //Step3 ：调用ip_out()函数将数据报发送出去。
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    //Step1 ：首先做报头检测，如果接收到的包长小于ICMP头部长度，则丢弃不处理。
    if (buf->len < sizeof(icmp_hdr_t))   
        return;
    //Step2 ：接着，查看该报文的ICMP类型是否为回显请求。
    //Step3 ：如果是，则调用icmp_resp()函数回送一个回显应答（ping 应答）。
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;
    if (icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST && icmp_hdr->code == 0)
            icmp_resp(buf, src_ip);
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    //Step1 ：首先调用buf_init()来初始化txbuf，填写ICMP报头首部。
    buf_init(&txbuf, sizeof(ip_hdr_t) + 8);

    //Step2 ：接着，填写ICMP数据部分，包括IP数据报首部和IP数据报的前8个字节的数据字段，填写校验和。
    memcpy(txbuf.data, recv_buf->data, sizeof(ip_hdr_t) + 8);
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));

    icmp_hdr_t *icmp_hdr = (icmp_hdr_t*)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->checksum16 = 0;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    //Step3 ：调用ip_out()函数将数据报发送出去。
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}