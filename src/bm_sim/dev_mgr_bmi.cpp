/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/dev_mgr.h>
 #include <bm/bm_sim/logger.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <iostream>

#include <string>
#include <cassert>
#include <mutex>
#include <map>

#include <sys/shm.h>
#include <pthread.h>
#include <time.h>

extern "C" {
  #include "BMI/bmi_port.h"
  
}

#define PACKET_QUEUE_LENGTH 65536
#define TX_SHM_KEY  12357
#define RX_SHM_KEY  12347

typedef void (*packet_handler_t)(int port_num, const char *buffer, int len, void *cookie);

struct packet {
  uint16_t ingress_port;
  uint16_t length;
  char data[1600];
};

struct packet_memory {
  int mutex;
  uint64_t head, tail;
  struct packet packet[PACKET_QUEUE_LENGTH];
};

typedef struct {
  void *cookie;
  struct packet_memory* rx_packet_memory;
  struct packet_memory* tx_packet_memory;
  packet_handler_t packet_handler;
} dpdk_port_mgr_t;


int get_shared_packet_memory(key_t key, struct packet_memory ** memory);
void init_packet_memory(struct packet_memory* memory) ;
void del_shared_packet_memory(void* shm, int shmid);
static inline 
void push_packet(struct packet_memory* pkts, const char* buf, uint16_t length, uint8_t port_id) {
  int head = (int)(pkts->head % PACKET_QUEUE_LENGTH);

  if(pkts->head>=(pkts->tail + PACKET_QUEUE_LENGTH-1)) {
    return;
  }

  memcpy(pkts->packet[head].data, buf, length);
  pkts->packet[head].length = length;
  pkts->packet[head].ingress_port = port_id;
  std::cout<<"STD TRANS"<<pkts->head<<std::endl;
  pkts->head = pkts->head + 1;
}

static inline
int pop_packet(struct packet_memory* pkts) {
  if(pkts->head <= pkts->tail) {
    return 0;
  }
  pkts->tail = pkts->tail + 1;
  return 1;
}

static inline 
int get_packet(struct packet_memory* pkts, char** buf, uint8_t *port_id) {
  int tail = (int)(pkts->tail % PACKET_QUEUE_LENGTH);
  struct packet *pkt;

  if(pkts->head <= pkts->tail) {
    return 0;
  }

  pkt = &pkts->packet[tail];
  *port_id = pkt->ingress_port;
  *buf = pkt->data;

  return pkt->length;
}

int get_shared_packet_memory(key_t key, struct packet_memory ** memory) {

  int shmid;
  void * shm;

  shmid = shmget(key, sizeof(struct packet_memory), IPC_CREAT);

  shm = shmat(shmid, (void*)0, 0);

  *memory = (struct packet_memory*)shm;

  return shmid;
}

void del_shared_packet_memory(void* shm,int shmid) {
  shmdt(shm);
  shmctl(shmid, IPC_RMID, 0);
}

static void *rx_pmd(void* data) {
  dpdk_port_mgr_t* port_mgr = (dpdk_port_mgr_t *)data;
  struct packet_memory* rx_packet_memory = port_mgr->rx_packet_memory;
  packet_handler_t packet_handler = port_mgr->packet_handler;
  char *buf;
  uint8_t port_id;
  int nb_recv;
  BMLOG_DEBUG("START DPDK SWITCH");
  while(1) {
    nb_recv = get_packet(port_mgr->rx_packet_memory, &buf, &port_id);
    if(nb_recv > 0) {
      packet_handler(port_id, (const char*)buf, nb_recv, port_mgr->cookie);
      pop_packet(rx_packet_memory);
    }
  }
  return NULL;
}


namespace bm {

class DPDKDevMgrImp : public DevMgrIface {
  public:


    typedef PortMonitorIface::port_t port_t;
    typedef PortMonitorIface::PortStatus PortStatus;
    typedef PortMonitorIface::PortStatusCb PortStatusCb;
    
    DPDKDevMgrImp(int device_id,
             std::shared_ptr<TransportIface> notifications_transport) {
      p_monitor = PortMonitorIface::make_active(device_id, notifications_transport);
      
      tx_shmid = get_shared_packet_memory((key_t)TX_SHM_KEY, &tx_packet_memory);
      rx_shmid = get_shared_packet_memory((key_t)RX_SHM_KEY, &rx_packet_memory);

      port_mgr = (dpdk_port_mgr_t*)malloc(sizeof(dpdk_port_mgr_t));
      port_mgr->tx_packet_memory = tx_packet_memory;
      port_mgr->rx_packet_memory = rx_packet_memory;
    }
  
    private:
      ReturnCode port_add_(const std::string &iface_name, port_t port_num,
                   const char *in_pcap, const char *out_pcap) override {
          PortInfo p_info(port_num, iface_name);
          (void)in_pcap;
          (void)out_pcap;
          //Lock lock(mutex);
          port_info.emplace(port_num, std::move(p_info));

        return ReturnCode::SUCCESS;
      }

      ReturnCode port_remove_(port_t port_num) override {
        (void)port_num;
        return ReturnCode::SUCCESS;
      }

      void transmit_fn_(int port_num, const char *buffer, int len) override {
        push_packet(tx_packet_memory, buffer, (uint16_t)len, (uint8_t)port_num);
      }

      void start_() override {
        pthread_create(&thread, NULL, rx_pmd, port_mgr);
      }

      ReturnCode set_packet_handler_(const PacketHandler &handler, void *cookie) override {
        typedef void function_t(int, const char *, int, void *);
        function_t * const*ptr_fun = handler.target<function_t *>();
        port_mgr->packet_handler = *ptr_fun;
        port_mgr->cookie = cookie;
        
        return ReturnCode::SUCCESS;
      }

      bool port_is_up_(port_t port) const override {
        (void)port;
        return true;
      }

      std::map<port_t, PortInfo> get_port_info_() const override {
        std::map<port_t, PortInfo> info;
        {
            //Lock lock(mutex);
            info = port_info;
        }
        for (auto &pi : info) {
            pi.second.is_up = port_is_up_(pi.first);
        } 
        return info;
      }

  private:
    using Mutex = std::mutex;
    using Lock = std::lock_guard<std::mutex>;

    pthread_t thread;
    int tx_shmid,rx_shmid;
    dpdk_port_mgr_t *port_mgr;
    mutable Mutex mutex;
    std::map<port_t, DevMgrIface::PortInfo> port_info;
    struct packet_memory* tx_packet_memory;
    struct packet_memory* rx_packet_memory;
};



void
DevMgr::set_dev_mgr_dpdk( int device_id, std::shared_ptr<TransportIface> notifications_transport) {
    assert(!pimp);
  pimp = std::unique_ptr<DevMgrIface>(
      new DPDKDevMgrImp(device_id, notifications_transport));
}

}


namespace bm {

// These are private implementations

// Implementation that uses the BMI to send/receive packets
// from true interfaces

// I am putting this in its own cpp file to avoid having to link with the BMI
// library in other DevMgr tests

class BmiDevMgrImp : public DevMgrIface {
 public:
  BmiDevMgrImp(int device_id,
               std::shared_ptr<TransportIface> notifications_transport) {
    assert(!bmi_port_create_mgr(&port_mgr));

    p_monitor = PortMonitorIface::make_active(device_id,
                                              notifications_transport);
  }

 private:
  ~BmiDevMgrImp() override {
    bmi_port_destroy_mgr(port_mgr);
  }

  ReturnCode port_add_(const std::string &iface_name, port_t port_num,
                       const char *in_pcap, const char *out_pcap) override {
    if (bmi_port_interface_add(port_mgr, iface_name.c_str(), port_num, in_pcap,
                               out_pcap))
      return ReturnCode::ERROR;

    PortInfo p_info(port_num, iface_name);
    if (in_pcap) p_info.add_extra("in_pcap", std::string(in_pcap));
    if (out_pcap) p_info.add_extra("out_pcap", std::string(out_pcap));

    Lock lock(mutex);
    port_info.emplace(port_num, std::move(p_info));

    return ReturnCode::SUCCESS;
  }

  ReturnCode port_remove_(port_t port_num) override {
    if (bmi_port_interface_remove(port_mgr, port_num))
      return ReturnCode::ERROR;

    Lock lock(mutex);
    port_info.erase(port_num);

    return ReturnCode::SUCCESS;
  }

  void transmit_fn_(int port_num, const char *buffer, int len) override {
    bmi_port_send(port_mgr, port_num, buffer, len);
  }

  void start_() override {
    assert(port_mgr);
    assert(!bmi_start_mgr(port_mgr));
  }

  ReturnCode set_packet_handler_(const PacketHandler &handler, void *cookie)
      override {
    typedef void function_t(int, const char *, int, void *);
    function_t * const*ptr_fun = handler.target<function_t *>();
    assert(ptr_fun);
    assert(*ptr_fun);
    assert(!bmi_set_packet_handler(port_mgr, *ptr_fun, cookie));
    return ReturnCode::SUCCESS;
  }

  bool port_is_up_(port_t port) const override {
    bool is_up = false;
    assert(port_mgr);
    int rval = bmi_port_interface_is_up(port_mgr, port, &is_up);
    is_up &= !(rval);
    return is_up;
  }

  std::map<port_t, PortInfo> get_port_info_() const override {
    std::map<port_t, PortInfo> info;
    {
      Lock lock(mutex);
      info = port_info;
    }
    for (auto &pi : info) {
      pi.second.is_up = port_is_up_(pi.first);
    }
    return info;
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<std::mutex>;

  bmi_port_mgr_t *port_mgr{nullptr};
  mutable Mutex mutex;
  std::map<port_t, DevMgrIface::PortInfo> port_info;
};

void
DevMgr::set_dev_mgr_bmi(
    int device_id, std::shared_ptr<TransportIface> notifications_transport) {
  assert(!pimp);
  pimp = std::unique_ptr<DevMgrIface>(
      new BmiDevMgrImp(device_id, notifications_transport));
}

}  // namespace bm
