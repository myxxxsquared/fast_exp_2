/** *************************************************************************
 *  @file          main_libreg.c
 *  @brief		FAST平台的硬件寄存器读写控制库
 * 
 *  FAST平台支持带CPU功能的设备（如OpenBox），同时也支持不带CPU的设备（如NetMagic 08）
 *  但FAST软件架构的设计将对硬件的寄存器操作全封装为统一接口形式，在本库内根据不同设备
 *  的特征进行不同的硬件寄存器访问操作。\n
 *  OpenBox设备是通过PICe的寄存器形式访问，NetMagic 08则是通过构造NMAC报文进行寄存器读写
 *  @date		2017/02/15 16:36:51 星期三
 *  @author		XDL(Copyright  2017  XuDongLai)
 *  @email		<XuDongLai0923@163.com>
 *  @version	0.2.0
 ****************************************************************************/
/*
 * main_libreg.c
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

#include "../include/fast.h"

/** @brief 寄存器读写功能库的版本号定义 */

#ifdef NetMagic08
#include "../include/fast.h"
#include <linux/ip.h>
#include <arpa/inet.h>

int exit_flag = 0;  /**< @brief NMAC接收报文的退出标志*/
int nm_skt = 0;		/**< @brief NMAC报文发送SOCKET的句柄*/
int recv_skt = 0;   /**< @brief NMAC报文接收SOCKET的句柄*/
struct sockaddr_in nm_addr; /**< @brief NetMagic 08设备的地址信息，默认硬件的IP地址为：136.136.136.136*/
/**
 * @brief 接收NMAC回应报文的格式定义
 * 
 * 由于通过原始套接字接收回报文，故接收到的为一个完整的以太网报文
 * 前面还包括以太网头和IP头部分
 */
struct recv_pkt
{
	struct ethhdr eth;	  /**< @brief 以太网头部*/
	struct iphdr ip;		/**< @brief IP头部*/
	struct nm_packet nh;	/**< @brief 完整NMAC报文部分*/
}__attribute__((packed));


/**
* @brief 打印接收NMAC报文功能函数
*
* @param pkt		：接收到的NMAC报文
* @param pkt_len	：打印此报文的长度 @warning 必须要小于等于接收NMAC报文的长度
*/
void print_nmac_pkt(struct recv_pkt *pkt,int pkt_len)
{
	int i=0;
	printf("-----------------------***NMAC PACKET***-----------------------\n");
	printf("Packet Addr:%p\n",pkt);
	for(i=0;i<16;i++)
	{
		if(i % 16 == 0)
			printf("      ");
		printf(" %X ",i);
		if(i % 16 == 15)
			printf("\n");
	}
	
	for(i=0;i<pkt_len;i++)
	{
		if(i % 16 == 0)
			printf("%04X: ",i);
		printf("%02X ",*((u8 *)pkt+i));
		if(i % 16 == 15)
			printf("\n");
	}
	if(pkt_len % 16 !=0)
		printf("\n");
	printf("-----------------------***NMAC PACKET***-----------------------\n\n");
}

/**
* @brief 开始接收NMAC回应报文功能函数
*
* @param pkt	：存储接收报文的指针
* @param len	：存储接收报文长度的指针 @note 接收报文有效长度通过些指针数据返回
*
* @return 
*/
int recv_nm_pkt(struct recv_pkt *pkt,int *len)
{	
	while(!exit_flag && (*len = recv(recv_skt,(u8 *)pkt, sizeof(struct recv_pkt),0)) > 0)
	{
		if(pkt->ip.protocol == NMAC_PROTO)
		{
			return 1;
		}
		else
		{
			//print_nmac_pkt(pkt,*len);
			//printf("pkt len:%d,proto:%d\n",*len,pkt->ip.protocol);
		}
	}		
	return 0;
}

/**
* @brief 发送NMAC报文功能函数
*
* @param pkt	：发送NMAC报文的指针
* @param len	：发送报文的长度
*
* @return   1：表示发送成功\n
			2：表示发送失败
*/
int send_nm_pkt(struct nm_packet *pkt,int len)
{
	return (len == sendto(nm_skt,(u8 *)pkt, len,0,(struct sockaddr*)&nm_addr,sizeof(nm_addr)));	
}


/**
* @brief 启动发送NMAC报文线程函数
*
* @param argv   ：线程参数，需要发送的报文指针存储在此，线程内部将此指导转化为NMAC报文指针
*
* @return 空
*/
void *send_thread(void *argv)
{
	struct nm_packet *pkt = (struct nm_packet *)argv;	
	if(!send_nm_pkt(pkt,sizeof(struct nm_packet)))
	{
		FAST_ERR("Send NMAC Failed!\n");		
	}
	free(pkt);
}


/**
* @brief NetMagic 08的连接操作函数
*
* @return   0：表示连接成功\n
			-1：表示连接失败
*/
int nm_connect(void)
{
	struct nm_packet *pkt = (struct nm_packet *)malloc(sizeof(struct nm_packet));
	struct recv_pkt *pkt2 = (struct recv_pkt *)malloc(sizeof(struct recv_pkt));
	int len = 0,ret = -1;
	pthread_t tid;
	
	pkt->nm.count = 1;
	pkt->nm.type = NM_CONN;
	if(pthread_create(&tid, NULL,send_thread, (void *)pkt))
	{
		FAST_ERR("Send NMAC CN PKT Failed!\n");
	}
	if(recv_nm_pkt(pkt2,&len) && pkt2->nh.nm.type == NM_CONN)
	{
		ret = 0;
	}
	free(pkt2);
	FAST_DBG("REG Version:%s,NetMagic08 HW Version:%lX\n",REG_VERSION,fast_reg_rd(FAST_HW_REG_VERSION));
	return ret;
}

/**
* @brief NetMagic 08释放连接操作（关闭操作）
*/
void nm_release(void)
{
	struct nm_packet *pkt = (struct nm_packet *)malloc(sizeof(struct nm_packet));
	struct recv_pkt *pkt2 = (struct recv_pkt *)malloc(sizeof(struct recv_pkt));
	int len = 0,ret = -1;
	pthread_t tid;
	
	pkt->nm.count = 1;
	pkt->nm.type = NM_RELESE;
	if(pthread_create(&tid, NULL,send_thread, (void *)pkt))
	{
		FAST_ERR("Send NMAC RELESE PKT Failed!\n");
	}
	if(recv_nm_pkt(pkt2,&len) && pkt2->nh.nm.type == NM_RELESE)
	{
		FAST_DBG("NMAC RELEASE OK!\n");
	}
	free(pkt2);	
}

/**
* @brief NetMagic 08硬件注销操作函数
 * 
 * 此功能通过信号机制来完成，一但程序中断或退出，则启动硬件的注销操作
*
* @param argc   中断信号（捕获Ctrl + C操作）
*/
void __distroy_NetMagic08(int argc)
{
	exit_flag = 1;
	nm_release();
}

/**
* @brief NetMagic 08的硬件初始化操作
*
 * NetMagic 08的硬件初始化操作主要包括对接收发送SOCKET句柄的初始化，硬件访问IP地址的初始化，
 * 绑定中断退出功能函数，配置硬件设备IP的ARP静态映射，最后发送连接报文进行连接
* @param addr   ：初始化硬件地址（NetMagic 08设备无效，可填0）
* @param len	：硬件地址的有效长度（NetMagic 08设备无效，可填0）
*
* @return 
*/
int init_hw_NetMagic08(u64 addr,u64 len)
{
	struct sockaddr_in sa;
	struct timeval recv_timeout={2,0};/*数据接收超时设置*/
	int ret = 0;
	
	bzero(&sa, sizeof(sa)); 
	bzero(&nm_addr, sizeof(nm_addr)); 
	sa.sin_family = AF_INET; 
	sa.sin_addr.s_addr = htonl(INADDR_ANY); 
	sa.sin_port = htons(123);

	nm_addr.sin_family = AF_INET; 
	nm_addr.sin_addr.s_addr = inet_addr("136.136.136.136");
	nm_addr.sin_port = htons(321); 
	/* 创建socket */
	if ((nm_skt = socket(AF_INET, SOCK_RAW,NMAC_PROTO)) < 0)//AF_INET,NMAC_PROTO,IPPROTO_ICMP
	{
		FAST_ERR("NMAC Send SKT Failed!\n");		
	}

	if ((recv_skt = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_IP))) < 0)//AF_INET,NMAC_PROTO,IPPROTO_ICMP
	{
		FAST_ERR("NMAC Recv SKT Failed!\n");
	}	
	ret = setsockopt(recv_skt,SOL_SOCKET,SO_RCVTIMEO,(const char*)&recv_timeout,sizeof(recv_timeout));

	/* 绑定*/
	if((bind(nm_skt,(struct sockaddr*)&sa,sizeof(sa))) == -1) 
	{ 
		FAST_ERR("NMAC Bind Failed!"); 
	}
	
	signal(SIGINT,__distroy_NetMagic08);				/*非法结束时，调用注销函数*/
	ret = system("arp -s 136.136.136.136 88:88:88:88:88:88");/*添加MAC与IP的静态映射规则*/
	usleep(20000);
	return nm_connect();
}

/**
* @brief NetMagic 08设备硬件注销操作函数
*/
void distroy_hw_NetMagic08(void)
{
	nm_release();
}


/**
* @brief NetMagic 08硬件寄存器读操作
*
* @param regaddr	：需要访问的硬件寄存器地址
*
* @return   返回该寄存器地址对应的值
* @note 寄存器地址和返回值均为64位无符号类型
*/
u64 NetMagic08_reg_rd(u64 regaddr)
{
	struct nm_packet *pkt = (struct nm_packet *)malloc(sizeof(struct nm_packet));
	struct recv_pkt *pkt2 = (struct recv_pkt *)malloc(sizeof(struct recv_pkt));
	int len = 0;
	u64 regvalue = 0;
	pthread_t tid;
	
	pkt->nm.count = 1;
	pkt->nm.type = NM_REG_RD;
	pkt->regaddr = htobe64(regaddr);
	if(pthread_create(&tid, NULL,send_thread, (void *)pkt))
	{
		FAST_ERR("Send NMAC RD PKT Failed!\n");
	}
	if(recv_nm_pkt(pkt2,&len) && pkt2->nh.nm.type == NM_RD_RPL && pkt2->nh.regaddr == htobe64(regaddr))
	{
			regvalue = be64toh(pkt2->nh.regvalue);
	}
	free(pkt2);
	return regvalue;
}


/**
* @brief NetMagic 08硬件寄存器写操作
*
* @param regaddr	：准备写操作的寄存器地址
* @param regvalue   ：准备写操作的寄存值
* @note 寄存器地址和返回值均为64位无符号类型
*/
void NetMagic08_reg_wr(u64 regaddr,u64 regvalue)
{
	struct nm_packet *pkt = (struct nm_packet *)malloc(sizeof(struct nm_packet));
	struct recv_pkt *pkt2 = (struct recv_pkt *)malloc(sizeof(struct recv_pkt));
	int len = 0;
	pthread_t tid;
	
	pkt->nm.count = 1;
	pkt->nm.type = NM_REG_WR;
	pkt->regaddr = htobe64(regaddr);
	pkt->regvalue = htobe64(regvalue);
	if(pthread_create(&tid, NULL,send_thread, (void *)pkt))
	{
		FAST_ERR("Send NMAC WR PKT Failed!\n");
	}
	if(recv_nm_pkt(pkt2,&len) && pkt2->nh.nm.type == NM_WR_RPL)// && pkt2->nh.regaddr == htobe64(regaddr))
	{
		free(pkt2);
		return;
	}
	FAST_ERR("WR REG ERR!\n");
}



#elif OpenBoxS28
/** 
 * @brief FAST设备的硬件基地址
 * 
 *  目前针对不同平台手动设置
 * @note 通过lspci -x 命令，查看FAST设备的BAR0地址空间（0x10偏移位置的4字节地址信息）
 *  @todo 以后将会修改为自动从系统读取
 */

u64 OBX_BASE_ADDR = 0x90980000;/*OpenBox on i7*/

/** 
 * @brief FAST设备硬件地址的有效空间大小
 * 
 * 目前手动设置为512K
 * @todo 以后将会修改为自动从系统读取
 */
u64 OBX_REG_LEN = 512*1024;

/** @brief 硬件设备的虚拟地址指针*/
void *npe_base = NULL;
int fm = 0;

/**
* @brief OpenBox设备的硬件资源注销函数
*/
void distroy_hw_OpenBox(void)
{
	if(npe_base != NULL)
	{
		munmap(npe_base,OBX_REG_LEN);
		close(fm);
		exit(0);
	}
}

/**
* @brief OpenBox设备的硬件资源注销，由退出中断信号调用
*
* @param argc   中断信号（捕获Ctrl + C操作）
*/
void __distroy_hw_OpenBox(int argc)
{
	printf("distroy_hw_OpenBox\n");
	distroy_hw_OpenBox();
}

int read_pcie_base(int vendor_id,int device_id)
{	
	char cmd[256]={0},value[1024]={0},value2[32]={0},value3[32]={0},value4='\0';
	int len = 0;
	FILE *stream = NULL;

	
	sprintf(cmd,"%s%X:%X%s","lspci -d ",vendor_id,device_id," -v|grep Memory");
	stream = popen(cmd,"r");
	len = fread(value,sizeof(char),sizeof(value),stream);
	if(len > 32)
	{		
		OBX_BASE_ADDR = 0;
		OBX_REG_LEN = 0;
		sscanf(value,"\tMemory at %llx %s %s [size=%lld%c]\n",&OBX_BASE_ADDR,value2,value3,&OBX_REG_LEN,&value4);//,value3,value4);// [size=%ldK],&OBX_REG_LEN);
		if(value4 == 'K')
			OBX_REG_LEN *=1024;
		else if(value4 == 'M')
			OBX_REG_LEN *=1024*1024;
	}
	pclose (stream);
}


/**
* @brief OpenBox设备硬件资源初始化函数
*
* @param addr   ：初始化硬件基地址
* @param len	：硬件地址的有效空间大小
*
* @return   0：表示初始化成功\n
* @warning	若不成功，则退出程序
*/
int init_hw_OpenBox(u64 addr,u64 len)
{	
	if((fm=open("/dev/mem",O_RDWR|O_SYNC)) == -1)
	{
		printf("Open MEM Err!\n");
		exit(0);
	}
	read_pcie_base(0x1172,0xE001);
	if(addr != 0 && len != 0)
	{
		OBX_BASE_ADDR = addr;
		OBX_REG_LEN = len;
	}
	npe_base = mmap(0,OBX_REG_LEN,PROT_READ|PROT_WRITE,MAP_SHARED,fm,OBX_BASE_ADDR);
	FAST_DBG("REG Version:%s,OpenBox HW Version:%llX\n",REG_VERSION,fast_reg_rd(FAST_HW_REG_VERSION));
	signal(SIGINT,__distroy_hw_OpenBox);//非法结束时，调用注销函数
	return 0;
}
#else
u64 ZYNQ_UM_ADDR  = 0x43C80000;
u64 ZYNQ_UM_SIZE  = 0x80000;

u64 ZYNQ_GME_ADDR = 0x43D00000;
u64 ZYNQ_GME_SIZE = 0x80000;

u64 ZYNQ_PORT_ADDR = 0x43D80000;
u64 ZYNQ_PORT_SIZE = 0x10000*4;

void *um_base = NULL,*gme_base = NULL,*port_base = NULL;;
int fm = 0;

void distroy_hw_ZYNQ(void)
{
	if(um_base != NULL)
	{
		munmap(um_base,ZYNQ_UM_SIZE);		
	}

	if(gme_base != NULL)
	{
		munmap(gme_base,ZYNQ_GME_SIZE);		
	}

	if(port_base != NULL)
	{
		munmap(port_base,ZYNQ_GME_SIZE);		
	}
	if(fm >0)
		close(fm);
	exit(0);
}

void __distroy_hw_ZYNQ(int argc)
{
	printf("distroy_hw_ZYNQ_BOX\n");
	distroy_hw_ZYNQ();
}

int init_hw_ZYNQ(u64 addr,u64 len)
{	
	if((fm=open("/dev/mem",O_RDWR|O_SYNC)) == -1)
	{
		printf("Open MEM Err!\n");
		exit(0);
	}
	if(addr != 0 && len != 0)
	{
		ZYNQ_UM_ADDR = addr;
		ZYNQ_UM_SIZE = len;
	}
	um_base = mmap(0,ZYNQ_UM_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED,fm,ZYNQ_UM_ADDR);
	gme_base = mmap(0,ZYNQ_GME_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED,fm,ZYNQ_GME_ADDR);
	port_base = mmap(0,ZYNQ_PORT_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED,fm,ZYNQ_PORT_ADDR);
	FAST_DBG("REG Version:%s,OpenBox-S* HW Version:%lluX\n",REG_VERSION,fast_reg_rd(0));
	signal(SIGINT,__distroy_hw_ZYNQ);//非法结束时，调用注销函数
	return 0;
}
#endif


/**
* @brief FAST设备的硬件初始化函数
*
* @param addr   ：初始化硬件基地址
* @param len	：硬件地址的有效空间大小
*
* @return   0：表示初始化成功\n
 *			其他或退出程序表示初始化失败
*/
int fast_init_hw(u64 addr,u64 len)
{
#if XDL_DEBUG
	return 0;
#elif OpenBoxS28
	return init_hw_OpenBox(addr,len);
#elif NetMagic08
	return init_hw_NetMagic08(addr,len);
#else
	return init_hw_ZYNQ(addr,len);
#endif
}

/**
* @brief FAST设备的硬件销毁函数
*/
void fast_distroy_hw(void)
{
#ifdef XDL_DEBUG
	return;

#elif NetMagic08
	distroy_hw_NetMagic08();
#elif OpenBoxS28
	distroy_hw_OpenBox();
#else
	distroy_hw_ZYNQ ();
#endif
}


#define REG *(volatile u64 *)
#define REG32 *(volatile u32 *)

/**
* @brief FAST设备的硬件寄存器读操作
*
* @param regaddr	：准备读操作的寄存器地址
*
* @return   返回该寄存器地址对应的值
*/
u64 fast_reg_rd(u64 regaddr)
{
#ifdef XDL_DEBUG
	//printf("reg_rd:%lX = %X\n",regaddr,0x0923);
	return 0x0923;
#elif NetMagic08
	return NetMagic08_reg_rd(regaddr);
#elif OpenBoxS28
	usleep(200);
	return REG(npe_base + regaddr);
#else
	return REG32(um_base + regaddr);
#endif
}

/**
* @brief FAST设备的硬件寄存器写操作
*
* @param regaddr	：准备写操作的寄存器地址
* @param regvalue   ：准备写操作的寄存值
*/
void fast_reg_wr(u64 regaddr,u64 regvalue)
{	
#ifdef XDL_DEBUG
	//printf("reg_wr:%lX = %lX\n",regaddr,regvalue);
	return;
#elif NetMagic08
	NetMagic08_reg_wr(regaddr,regvalue);
#elif OpenBoxS28
	REG(npe_base + regaddr) = regvalue;
	usleep(200);
#else
	REG32(um_base + regaddr) = regvalue;
#endif
}


u32 fast_GME_reg_rd(u32 regaddr)
{
#ifdef XDL_DEBUG
	//printf("reg_rd:%lX = %X\n",regaddr,0x0923);
	return 0x0923;
#elif NetMagic08
	return NetMagic08_reg_rd(regaddr);
#elif OpenBoxS28
	usleep(200);
	return REG(npe_base + regaddr);
#else
	return REG32(gme_base + regaddr);
#endif
}

void fast_GME_reg_wr(u32 regaddr,u32 regvalue)
{
#ifdef XDL_DEBUG
	//printf("reg_wr:%lX = %lX\n",regaddr,regvalue);
	return;
#elif NetMagic08
	NetMagic08_reg_wr(regaddr,regvalue);
#elif OpenBoxS28
	REG(npe_base + regaddr) = regvalue;
	usleep(200);
#else
	REG32(gme_base + regaddr) = regvalue;
#endif
}

u64 fast_PORT_rd(u32 port,u32 regaddr)
{	
#ifdef XDL_DEBUG
	return 0x0923;
#elif OpenBoxS28
	return;
#else
//printf("port:%d,addr:%X,base:%X,real:%X,value:%X\n",port,regaddr,port_base,port_base + port*FAST_PORT_OFT + regaddr,REG32(port_base + port*FAST_PORT_OFT + regaddr));

	//usleep(5000);
	return REG32(port_base + port*0x10000 + regaddr);
#endif
}

void fast_PORT_wr(u32 port,u32 regaddr,u32 regvalue)
{
#ifdef XDL_DEBUG
	return;
#elif OpenBoxS28
	return;
#else
	REG32(port_base + port*FAST_PORT_OFT + regaddr) = regvalue;
#endif
}
