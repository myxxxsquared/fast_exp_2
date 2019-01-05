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
 * 
 *  @date	   2019/01/05 星期六
 *  @author		Zhang Wenjie (Copyright 2019 Zhang Wenjie)
 *  @email		<zhang_a_a_a@outlook.com>
 *  @version	?
 ****************************************************************************/
/*
 * main_l2switch.c
 *
 * Copyright (C) 2017 - XuDongLai
 * Copyright (C) 2019 - HuNan ZhangWenjie
 * 
 * 解决输入输出端口一致时的泛洪问题
 * 改用C++
 * 修改了存储数据结构，改为二叉树
 * 加入了环路检测
 * 加入了硬件直接转发

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

#include "../include/fast.h"

#define NM08_PORT_CNT 4	/*设备端口数量*/
#define MAC_LEN 6		   /*MAC地址长度*/
#define MAC_LIFE_TIME 300  /*MAC地址生命时长为300秒，可调整*/
#define WAITING_QUEUE 20

#include <map>
#include <queue>
#include <cassert>

void pkt_send_flood(struct fast_packet *pkt, int pkt_len);
void pkt_send_normal(struct fast_packet *pkt, int pkt_len);

#define l2dbg(args...)  \
	do                  \
	{                   \
		printf(args);   \
		fflush(stdout); \
	} while (0)
// #define l2dbg(args...) void(0)

// 储存一个mac地址，并进行比较
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

// 一个mac地址的状态，包括端口号和过期时间
class port_status
{
  public:
	int port;
	time_t exptime;
};

// 线程锁
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

// 环路检测发送的数据包
static char loopdetectpacket_data[128] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xb4, 0x82, 0xe4, 0x67, 0x56, 0xac,
	0x88, 0xb5};

// 储存交换机当前状态信息，完成交换功能
class l2switchinfo
{
  public:
	// 转发接口信息
	std::map<mac_struct, port_status> flist;
	pthread_mutex_t flist_mutex;

	// 队列信息
	std::queue<struct fast_packet> packets;
	pthread_mutex_t packets_mutex;
	pthread_cond_t packets_come;
	struct fast_packet packet;

	// 环路检测信息
	bool packet_loop_detect[NM08_PORT_CNT];
	volatile bool finished_detection;

	// 包到达个数
	int packet_count;

	// 写入硬件的规则信息
	std::map<mac_struct, int> ruleport;
	int rulecur;
	bool learning;

	// 构造函数，初始化各个变量
	l2switchinfo();

	// 将数据包押入队列
	void push_packet(const struct fast_packet *packet);
	// 从队列中取出一个包
	void pop_packet();
	// 处理刚刚取出的包
	void process_packet();

	// 从src mac学习
	void learn(const mac_struct &mac, int port);
	// 查找 dst mac
	int find(mac_struct &mac);

	// 执行过期检测操作
	void exp();

	// 检测环路
	void testloop();

	// 向硬件写入规则
	int write_rule(const mac_struct &mac, int port);
	// 从硬件删除规则
	int del_rule(const mac_struct &mac);
	// 由学习状态转换为转发状态
	void learn_to_forawrd();
	// 由转发状态转换为学习状态
	void forawrd_to_learn();
};

static l2switchinfo l2info;

void l2switchinfo::learn(const mac_struct &mac, int port)
{
	pthread_mutec_locker locker{&flist_mutex};
	bool hardupdate = false;
	auto it = flist.find(mac);
	if (it == flist.end())
	{
		// new item
		flist[mac].exptime = time(0) + MAC_LIFE_TIME;
		flist[mac].port = port;
		hardupdate = true;
	}
	else
	{
		// old item
		it->second.exptime = time(0) + MAC_LIFE_TIME;
		if (it->second.port != port)
		{
			it->second.port = port;
			// new port
			hardupdate = true;
		}
	}

	if (hardupdate)
		l2dbg("learn ");

	if (hardupdate && !learning)
	{
		write_rule(mac, port);
	}
}

int l2switchinfo::find(mac_struct &mac)
{
	pthread_mutec_locker locker{&flist_mutex};
	auto it = flist.find(mac);
	if (it == flist.end())
		return -1;
	return it->second.port;
}

void l2switchinfo::exp()
{
	l2dbg("\nexp");
	time_t now = time(0);
	pthread_mutec_locker locker{&flist_mutex};
	for (auto it = flist.cbegin(); it != flist.cend();)
	{
		if (it->second.exptime < now)
		{
			if (!learning)
				del_rule(it->first);
			it = flist.erase(it);
		}
		else
		{
			++it;
		}
	}
}

void l2switchinfo::testloop()
{
	l2dbg("\nloop detection ");
	struct fast_packet loopdetectpacket;
	memset(&loopdetectpacket, 0, sizeof(struct fast_packet));
	loopdetectpacket.um.pktsrc = 1;
	loopdetectpacket.um.pktdst = 0;
	loopdetectpacket.um.dstmid = 5;
	loopdetectpacket.um.len = sizeof(loopdetectpacket_data);
	memcpy(loopdetectpacket.data, loopdetectpacket_data, sizeof(loopdetectpacket_data));

	for (int i = 0; i < NM08_PORT_CNT; ++i)
		packet_loop_detect[i] = false;

	for (int i = 0; i < NM08_PORT_CNT; ++i)
	{
		if (packet_loop_detect[i])
			continue;
		l2dbg("\nloop detection port %d ", i);
		loopdetectpacket.um.outport = i;
		fast_ua_send(&loopdetectpacket, loopdetectpacket.um.len);
		sleep(1); // wait for seconds;
	}

	finished_detection = true;
}

void l2switchinfo::learn_to_forawrd()
{
	l2dbg("\nlearn_to_forawrd");
	pthread_mutec_locker locker{&flist_mutex};
	for (auto it = flist.begin(); it != flist.end(); ++it)
	{
		write_rule(it->first, it->second.port);
	}
	learning = false;

	// print_hw_rule();
}

void l2switchinfo::forawrd_to_learn()
{
	l2dbg("\nforawrd_to_learn");
	pthread_mutec_locker locker{&flist_mutex};
	learning = true;
	for (int i = FAST_RULE_CNT - 1; i >= 0; --i)
		fast_del_rule(i);
	rulecur = 0;
	ruleport.clear();
}

int l2switchinfo::write_rule(const mac_struct &mac, int port)
{
	auto it = ruleport.find(mac);
	int ruleidx = 0;
	if (it != ruleport.end())
	{
		// find rule
		ruleidx = it->second;
	}
	else
	{
		//not find rule
		if (rulecur + 2 > FAST_RULE_CNT) // full
			return -1;
		ruleidx = rulecur;
		ruleport[mac] = ruleidx;
		rulecur += 2;
	}

	struct fast_rule rule1, rule2;
	memset(&rule1, 0, sizeof(struct fast_rule));
	memset(&rule2, 0, sizeof(struct fast_rule));

	u8 *smac, *dmac;
	smac = (u8 *)&mac;
	dmac = rule1.key.dmac;
	for (int i = 0; i < MAC_LEN; ++i)
		dmac[i] = smac[MAC_LEN - 1 - i];

	// rule1 drop packet from dst
	rule1.action = ACTION_DROP << 28;
	rule1.mask.port = -1;
	rule1.key.port = port;
	memset(rule1.mask.dmac, -1, MAC_LEN);
	rule1.valid = 1;
	rule1.priority = 1;

	// rule2 forward packet
	rule2.action = ACTION_PORT << 28 | port;
	memset(rule2.mask.dmac, -1, MAC_LEN);
	memcpy(rule2.key.dmac, rule1.key.dmac, MAC_LEN);
	rule2.valid = 1;

	fast_modify_rule(&rule1, ruleidx);
	fast_modify_rule(&rule2, ruleidx + 1);

	return ruleidx;
}

int l2switchinfo::del_rule(const mac_struct &mac)
{
	auto it = ruleport.find(mac);
	if (it != ruleport.end())
	{
		// find rule
		struct fast_rule rule;
		memset(&rule, 0, sizeof(struct fast_rule));
		fast_del_rule(it->second);
		fast_del_rule(it->second + 1);
		ruleport.erase(it);
	}
}

void l2switchinfo::push_packet(const struct fast_packet *packet)
{
	pthread_mutec_locker locker{&packets_mutex};
	if (packets.size() > WAITING_QUEUE)
		return;
	packets.push(*packet);
	pthread_cond_signal(&packets_come);
}

void l2switchinfo::pop_packet()
{
	pthread_mutec_locker locker{&packets_mutex};
	while (packets.empty())
	{
		pthread_cond_wait(&packets_come, &packets_mutex);
	}
	memcpy(&packet, &packets.front(), sizeof(struct fast_packet));
	packets.pop();
}

l2switchinfo::l2switchinfo()
{
	pthread_mutex_init(&flist_mutex, NULL);
	pthread_mutex_init(&packets_mutex, NULL);
	pthread_cond_init(&packets_come, NULL);
	for (int i = 0; i < NM08_PORT_CNT; ++i)
		packet_loop_detect[i] = false;
	finished_detection = false;
	packet_count = 0;

	rulecur = 0;
	learning = true;
}

void l2switchinfo::process_packet()
{
	struct fast_packet *pkt = &packet;
	int pkt_len = pkt->um.len;

	l2dbg("\n%08d %d %d %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ", packet_count++, pkt_len, (int)pkt->um.inport,
		  pkt->data[6], pkt->data[7], pkt->data[8], pkt->data[9], pkt->data[10], pkt->data[11],
		  pkt->data[0], pkt->data[1], pkt->data[2], pkt->data[3], pkt->data[4], pkt->data[5]);

	if (pkt->um.len == sizeof(loopdetectpacket_data) && memcmp(pkt->data, loopdetectpacket_data, sizeof(loopdetectpacket_data)) == 0)
	{
		l2dbg("loop detected %d\n", (int)pkt->um.inport);
		packet_loop_detect[pkt->um.inport] = true;
		return;
	}

	if (!finished_detection)
		return;

	if (packet_loop_detect[pkt->um.inport])
	{
		l2dbg("loop packet dropped %d\n", (int)pkt->um.inport);
		return;
	}

	learn(*(mac_struct *)&pkt->data[MAC_LEN], pkt->um.inport);
	int oport = find(*(mac_struct *)&pkt->data[0]);
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

/*转发单个包*/
void pkt_send_normal(struct fast_packet *pkt, int pkt_len)
{
	// l2dbg("pkt_send_normal->%p,outport:%d,len:%d\n",pkt,(int)pkt->um.outport,pkt_len);
	l2dbg("send %d ", (int)pkt->um.outport);
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
	l2dbg("flood ");
	for (; i < NM08_PORT_CNT; i++) /*除输入端口外，其他都发送一份*/
	{
		if (i != inport && !l2info.packet_loop_detect[i])
		{
			pkt->um.outport = i;
			pkt_send_normal(pkt, pkt_len);
		}
	}
}

/*处理过期和学习状态*/
void *aging_and_learning(void *argv)
{
	while (1)
	{
		sleep(1);
		if (!l2info.finished_detection)
			continue;

		l2info.exp();
		l2info.forawrd_to_learn();
		sleep(1);
		l2info.learn_to_forawrd();
		sleep(30);
	}
}

/*处理到来的包*/
void *process_pkt(void *argv)
{
	while (1)
	{
		l2info.pop_packet();
		l2info.process_packet();
	}
}

/*执行环路检测*/
void *looptest(void *argv)
{
	while (true)
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

int main(int argc, char *argv[])
{
	/*初始化平台硬件*/
	fast_init_hw(0, 0);

	/*UA模块初始化	*/
	if (fast_ua_init(129, callback))
	{
		perror("fast_ua_init!\n");
		return 1;
	}

	/*配置硬件规则，将硬件所有报文送到模块ID为1的进程处理*/
	init_rule(ACTION_SET_MID << 28 | 129);

	pthread_t tid;
	// 启动线程处理环路
	pthread_create(&tid, NULL, looptest, NULL);
	// 启动线程处理老化
	pthread_create(&tid, NULL, aging_and_learning, NULL);
	// 启动线程进行数据包处理
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
