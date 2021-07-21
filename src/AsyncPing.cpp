#include <Esp.h>
#include "AsyncPing.h"

#ifdef ARDUINO_ARCH_ESP32
#include <WiFi.h>
#endif

#ifdef ARDUINO_ARCH_ESP8266
#include "ESP8266WiFi.h"
#endif

/* XXX use __typeof__ instead of typeof becaus -std=c++11 is used in ESP8266
 * build.
 *
 * https://gcc.gnu.org/onlinedocs/gcc/Typeof.html
 */
#ifdef ARDUINO_ARCH_ESP8266
#define typeof(x) __typeof__(x)
#endif

extern "C" {
  #include <lwip/icmp.h>
  #include <lwip/sys.h>
  #include <lwip/inet_chksum.h>
}

#define PING_DATA_SIZE 64 - 8

AsyncPing::AsyncPing() {
  ping_id = random(1 << 31);
  ping_pcb = NULL;
  _on_recv = NULL;
  _on_sent = NULL;
  count_down = 0;
}

AsyncPing::~AsyncPing() {
  _timer.detach();
  _timer_recv.detach();
  done();
}

void AsyncPing::on(bool mode, THandlerFunction fn) {
  if(mode)
    _on_recv=fn;
  else
    _on_sent=fn;
}

bool AsyncPing::begin(const IPAddress &addr,u8_t count,u32_t timeout) {
  if(!count || count_down)
    return false;
  _response.icmp_seq = 0;
  _response.total_sent = 0;
  _response.total_recv = 0;
  _response.total_time = 0;
  _response.addr = addr;
  _response.timeout = timeout;
  _response.mac = NULL;
  count_down = count;
  if (!ping_pcb) {
    ping_pcb = raw_new(IP_PROTO_ICMP);
    raw_recv(ping_pcb, _s_ping_recv, reinterpret_cast<void*>(this));
    raw_bind(ping_pcb, IP_ADDR_ANY);
  }

#ifdef ARDUINO_ARCH_ESP8266
  /* old esp8266/arduino does not support IPv6. but to use ICMP on ESP32,
   * IPv6-ready ip_addr_t must be used.
   */
  ping_target.addr = addr;
#else
  ping_target.type = IPADDR_TYPE_V4;
  ping_target.u_addr.ip4.addr = addr;
#endif
  ping_sent = sys_now(); // micro? system_get_time();
  send_packet();
  return true;
}

bool AsyncPing::begin(const char *host, u8_t count, u32_t timeout) {
  IPAddress ip;
  if (WiFi.hostByName(host, ip))
    return begin(ip, count, timeout);
  return false;
}

void AsyncPing::send_packet() {
  _response.answer = false;
  ping_send(ping_pcb, &ping_target);
  _response.total_sent++;
  count_down--;
  _timer.detach();
  _timer.attach<typeof(this)>(
          1.0,
          [](typeof(this) p){ p->_s_timer(p); },
          this);
}

void AsyncPing::cancel() {
  count_down = 0;
}

void AsyncPing::timer() {
  _timer.detach();
  if(!_response.answer)
    if(_on_recv)
      if(_on_recv(_response))
        cancel();
  if(count_down){
    send_packet();
  }else{
    _response.total_time = sys_now() - ping_sent; //micro? system_get_time()
    if(_on_sent)
      _on_sent(_response);
    done();
  }
}

void AsyncPing::done() {
  if (ping_pcb) {
    raw_remove(ping_pcb);
    ping_pcb = NULL;
  }
}

void AsyncPing::ping_send(struct raw_pcb *raw, ip_addr_t *addr) {
  struct pbuf *p = NULL;
  struct icmp_echo_hdr *iecho = NULL;
  _response.size = sizeof(struct icmp_echo_hdr) + PING_DATA_SIZE;

  p = pbuf_alloc(PBUF_IP, (u16_t)_response.size, PBUF_RAM);
  if (!p) {
    return;
  }
  if ((p->len == p->tot_len) && (p->next == NULL)) {
    iecho = (struct icmp_echo_hdr *)p->payload;

    ping_prepare_echo(iecho, (u16_t)_response.size);
    raw_sendto(raw, p, addr);
    ping_start = sys_now();
  }
  pbuf_free(p);
}

void AsyncPing::ping_prepare_echo(struct icmp_echo_hdr *iecho, u16_t len) {
  size_t i = 0;
  size_t data_len = len - sizeof(struct icmp_echo_hdr);

  ICMPH_TYPE_SET(iecho, ICMP_ECHO);
  ICMPH_CODE_SET(iecho, 0);
  iecho->chksum = 0;
  iecho->id     = ping_id;
  ++ _response.icmp_seq;
  if (_response.icmp_seq == 0x7fff)
    _response.icmp_seq = 0;

  iecho->seqno = htons(_response.icmp_seq);

  /* fill the additional data buffer with some data */
  for(i = 0; i < data_len; i++) {
    ((char*)iecho)[sizeof(struct icmp_echo_hdr) + i] = (char)i;
  }

  iecho->chksum = inet_chksum(iecho, len);
}

u8_t AsyncPing::ping_recv (raw_pcb*pcb, pbuf*p, C_IP_ADDR ip_addr_t *addr) {
  struct icmp_echo_hdr *iecho = NULL;
  struct ip_hdr *ip = (struct ip_hdr *)p->payload;
  if (pbuf_header( p, -PBUF_IP_HLEN) == 0) {
    iecho = (struct icmp_echo_hdr *)p->payload;
    if ((iecho->id == ping_id) && (iecho->seqno == htons(_response.icmp_seq)) && iecho->type == ICMP_ER) {
      _response.time = sys_now() - ping_start;
      _response.ttl = ip->_ttl;
      _response.answer = true;
      _response.total_recv++;
#ifdef ARDUINO_ARCH_ESP8266
      C_IP_ADDR ip_addr_t *unused_ipaddr;
      if (_response.mac == NULL)
        etharp_find_addr(NULL, addr, &_response.mac, &unused_ipaddr);
#else
      C_IP_ADDR ip4_addr_t *unused_ipaddr;
      if (_response.mac == NULL) {
        ip4_addr_t ip4 = addr->u_addr.ip4;
        etharp_find_addr(NULL, &ip4, &_response.mac, &unused_ipaddr);
      }
#endif
      if (_on_recv){
        _timer_recv.detach();
        _timer.attach<typeof(this)>(
          1.0,
          [](typeof(this) p){ p->_s_timer_recv(p); },
          this);
      }
      pbuf_free(p);
      return 1; /* eat the packet */
    }
  }
  pbuf_header( p, PBUF_IP_HLEN);
  return 0; /* don't eat the packet */
}

u8_t AsyncPing::_s_ping_recv (void*arg, raw_pcb*tpcb, pbuf*pb, C_IP_ADDR ip_addr_t *addr){
  return reinterpret_cast<AsyncPing*>(arg)->ping_recv(tpcb, pb, addr);
}

void AsyncPing::_s_timer (void*arg){
  return reinterpret_cast<AsyncPing*>(arg)->timer();
}
void AsyncPing::_s_timer_recv (void*arg){
  AsyncPing &host = *reinterpret_cast<AsyncPing*>(arg);
  host._timer_recv.detach();
  if (host._on_recv)
    if(host._on_recv(host._response))
      host.cancel();
}
