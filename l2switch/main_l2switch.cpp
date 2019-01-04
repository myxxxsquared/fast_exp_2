/** *************************************************************************
 *  @file          main_l2switch.c
 *  @brief	  基于FAST架构的软件二层交换示例程序
 * 
 *  详细说明
 * 
 *  @date	   2017/04/08 10:39:17 星期六
 *  @author		XDL(Copyright  2017  XuDongLai)
 *  @email		<XuDongLai0923@163.com>
 *  @version	0.2.0
 ****************************************************************************/
/*
 * main_l2switch.c
 *
 * Copyright (C) 2017 - XuDongLai
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

//解决输入输出端口一致时的泛洪问题

#include "../include/fast.h"

#define NM08_PORT_CNT 4	/*设备端口数量*/
#define NM08_NEIGH_MAX 128 /*每个端口上最大存储邻居MAC个数*/
#define MAC_LEN 6		   /*MAC地址长度*/
#define MAC_LIFE_TIME 300  /*MAC地址生命时长为300秒，可调整*/
#define WAITING_QUEUE 20

#include <map>
#include <queue>
#include <cassert>

#define l2dbg(args...) printf(args)
// #define l2dbg(args...) void(0)

struct mac_struct
{
  public:
	u16 data[3];

	bool operator==(const struct mac_struct &rhs) const
	{
		return data[0] == rhs.data[0] && data[1] == rhs.data[1] && data[2] == rhs.data[2];
	}

	bool operator<(const struct mac_struct &rhs) const
	{
		return data[0] < rhs.data[0] || data[0] == rhs.data[0] && (data[1] < rhs.data[1] || data[1] == rhs.data[1] && data[2] < rhs.data[2]);
	}
};

class port_status
{
  public:
	int port;
	time_t exptime;
};

class pthread_mutec_locker
{
  public:
	pthread_mutex_t *mutex;
	pthread_mutec_locker(pthread_mutex_t *_mutex) : mutex(_mutex)
	{
		pthread_mutex_lock(mutex);
	}
	~pthread_mutec_locker()
	{
		pthread_mutex_unlock(mutex);
	}

	pthread_mutec_locker(const pthread_mutec_locker &) = delete;
	pthread_mutec_locker &operator=(const pthread_mutec_locker &) = delete;
};

static char loopdetectpacket_data[128] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xb4, 0x82, 0xe4, 0x67, 0x56, 0xac,
	0x88, 0xb5
};

class l2switchinfo
{
  public:
	std::map<mac_struct, port_status> flist;
	pthread_mutex_t flist_mutex;

	std::queue<struct fast_packet> packets;
	pthread_mutex_t packets_mutex;
	pthread_cond_t packets_come;
	struct fast_packet packet;

	bool packet_loop_detect[NM08_PORT_CNT];
	bool finished_detection;

	int packet_count;

	void push_packet(const struct fast_packet* packet)
	{
		pthread_mutec_locker locker{&packets_mutex};
		if(packets.size() > WAITING_QUEUE)
			return;
		packets.push(*packet);
		pthread_cond_signal(&packets_come);
	}

	void pop_packet()
	{
		pthread_mutec_locker locker{&packets_mutex};
		while(packets.empty())
		{
			pthread_cond_wait(&packets_come, &packets_mutex);
		}
		memcpy(&packet, &packets.back(), sizeof(struct fast_packet));
		packets.pop();
	}

	l2switchinfo()
	{
		l2dbg("init tmux\n");
		pthread_mutex_init(&flist_mutex, NULL);
		pthread_mutex_init(&packets_mutex, NULL);
		pthread_cond_init(&packets_come, NULL);
		for(int i = 0; i < NM08_PORT_CNT; ++i)
			packet_loop_detect[i] = false;
		finished_detection = false;
		packet_count = 0;
	}

	void learn(const mac_struct &mac, int port)
	{
		l2dbg("learn\n");
		pthread_mutec_locker locker{&flist_mutex};
		flist[mac].exptime = time(0) + MAC_LIFE_TIME;
		flist[mac].port = port;
	}

	int find(mac_struct &mac)
	{
		l2dbg("find\n");
		pthread_mutec_locker locker{&flist_mutex};
		auto it = flist.find(mac);
		if (it == flist.end())
			return -1;
		return it->second.port;
	}

	void exp()
	{
		l2dbg("exp\n");
		time_t now = time(0);
		pthread_mutec_locker locker{&flist_mutex};
		for (auto it = flist.cbegin(); it != flist.cend();)
		{
			if (it->second.exptime < now)
			{
				it = flist.erase(it);
			}
			else
			{
				++it;
			}
		}
	}

	void testloop()
	{
		l2dbg("loop detection \n");
		struct fast_packet loopdetectpacket;
		memset(&loopdetectpacket, 0, sizeof(struct fast_packet));
		loopdetectpacket.um.pktsrc = 1;
		loopdetectpacket.um.pktdst = 0;
		loopdetectpacket.um.dstmid = 5;
		loopdetectpacket.um.len = sizeof(loopdetectpacket_data);
		memcpy(loopdetectpacket.data, loopdetectpacket_data, sizeof(loopdetectpacket_data));

		for(int i = 0; i < NM08_PORT_CNT; ++i)
			packet_loop_detect[i] = false;

		for(int i = 0; i < NM08_PORT_CNT; ++i)
		{
			if(packet_loop_detect[i])
				continue;
			l2dbg("port %d\n", i);
			loopdetectpacket.um.outport = i;
			fast_ua_send(&loopdetectpacket, loopdetectpacket.um.len);
			sleep(5); // wait for seconds;
		}

		finished_detection = true;
	}
};

static l2switchinfo l2info;

/*转发单个包*/
void pkt_send_normal(struct fast_packet *pkt, int pkt_len)
{
	// l2dbg("pkt_send_normal->%p,outport:%d,len:%d\n",pkt,(int)pkt->um.outport,pkt_len);
	l2dbg("send %d\n", (int)pkt->um.outport);
	pkt->um.pktsrc = 1; /*报文来源为CPU输入*/
	pkt->um.pktdst = 0; /*报文目的为硬件输出*/
	pkt->um.dstmid = 5; /*直接从硬件GOE模块输出，不走解析、查表等模块*/
	fast_ua_send(pkt, pkt_len);
}

/*泛洪转发，会调用转发单个包的函数*/
void pkt_send_flood(struct fast_packet *pkt, int pkt_len)
{
	int i = 0, inport = pkt->um.inport; /*保存输入端口*/
	// l2dbg("-------pkt_send_flood\n");
	l2dbg("flood\n");
	for (; i < NM08_PORT_CNT; i++) /*除输入端口外，其他都发送一份*/
	{
		if (i != inport && !l2info.packet_loop_detect[i])
		{
			pkt->um.outport = i;
			pkt_send_normal(pkt, pkt_len);
		}
	}
}

/*MAC地址老化处理线程*/
void *nm08_mac_aging(void *argv)
{
	while (1)
	{
		sleep(10);
		l2info.exp();
	}
}

void *process_pkt(void *argv)
{
	struct fast_packet *pkt;
	int pkt_len;

	while(1)
	{
		l2info.pop_packet();
		pkt = &l2info.packet;
		pkt_len = pkt->um.len;

		l2dbg("\n%08d %d %d %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n", l2info.packet_count++, pkt_len,(int)pkt->um.inport,
			pkt->data[6], pkt->data[7], pkt->data[8], pkt->data[9], pkt->data[10], pkt->data[11],
			pkt->data[0], pkt->data[1], pkt->data[2], pkt->data[3], pkt->data[4], pkt->data[5]);

		if(pkt->um.len == sizeof(loopdetectpacket_data) && memcmp(pkt->data, loopdetectpacket_data, sizeof(loopdetectpacket_data)) == 0)
		{
			l2dbg("\nloop detected %d\n", (int)pkt->um.inport);
			l2info.packet_loop_detect[pkt->um.inport] = true;
			continue;
		}

		if(!l2info.finished_detection)
			continue;

		if(l2info.packet_loop_detect[pkt->um.inport])
		{
			l2dbg("\nloop packet dropped %d\n", (int)pkt->um.inport);
			continue;
		}

		l2info.learn(*(mac_struct *)&pkt->data[MAC_LEN], pkt->um.inport);
		int oport = l2info.find(*(mac_struct *)&pkt->data[0]);
		if (oport == -1)
		{
			pkt_send_flood(pkt, pkt_len);
		}
		else if (oport == pkt->um.inport)
		{
		}
		else
		{
			pkt->um.outport = oport;
			pkt_send_normal(pkt, pkt_len);
		}
	}
}

void *looptest(void *argv)
{
	while(true)
	{
		l2info.testloop();
		sleep(30);
	}
}

/*报文查表寻找目标端口、更新mac地址表和发送流程*/
int callback(struct fast_packet *pkt, int pkt_len)
{
	assert((int)pkt->um.len == pkt_len);
	l2info.push_packet(pkt);

	return 0;
}

void ua_init(void)
{
	int ret = 0;
	/*向系统注册，自己进程处理报文模块ID为1的所有报文*/
	if ((ret = fast_ua_init(129, callback))) //UA模块实例化(输入参数1:接收模块ID号,输入参数2:接收报文的回调处理函数)
	{
		perror("fast_ua_init!\n");
		exit(ret); //如果初始化失败,则需要打印失败信息,并将程序结束退出!
	}
}

int main(int argc, char *argv[])
{
	/*初始化平台硬件*/
	fast_init_hw(0, 0);

	/*UA模块初始化	*/
	ua_init();

	/*配置硬件规则，将硬件所有报文送到模块ID为1的进程处理*/
	init_rule(ACTION_SET_MID << 28 | 129);

	pthread_t tid;
	pthread_create(&tid, NULL, looptest, NULL);
	pthread_create(&tid, NULL, nm08_mac_aging, NULL);
	pthread_create(&tid, NULL, process_pkt, NULL);

	/*启动线程接收分派给UA进程的报文*/
	fast_ua_recv();

	/*主进程进入循环休眠中,数据处理主要在回调函数*/
	while (1)
	{
		sleep(9999);
	}
	return 0;
}
