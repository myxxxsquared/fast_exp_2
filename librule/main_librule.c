/** *************************************************************************
 *  @file          main_librule.c
 *  @brief	  FAST平台硬件流表配置支持库
 * 
 *  FAST平台硬件支持可编程功能，硬件提供256字节宽度的查表匹配引擎，软硬件可协同
 * 操作流表（软件配置的流表序列要与硬件提取的关键字序列一一对应），该支持库提供
 * 了一种通过流表的操作方法，具体流表结构可参考FAST平台硬件规则数据结构定义 @see ::fast_rule
 * 
 *  @date		2017/01/05 13:24:53 星期四
 *  @author		XDL(Copyright  2017  XuDongLai)
 *  @email		<XuDongLai0923@163.com>
 *  @version	0.2.0
 ****************************************************************************/
/*
 * main_librule.c
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

#define RULE_LEN sizeof(struct fast_rule)   /**< @brief 一条硬件流表的数据结构大小宏定义 256字节*/


/**
 * @brief FAST软件流表（二维数组表）定义
 *
 */ 
struct rule_table
{
	u64 cnt;		/**< @brief 软件流表条数*/
	u64 pad;		/**< 为使流表对齐访问使用的填充字段*/
	struct fast_rule rules[FAST_RULE_CNT];  /**< @brief 软件流表二维数组*/
};

/**
 * @brief 写流表数据时的结构体定义
 *
 */ 
struct reg_value{
		u32 v[1];
};


int rule_idx = 0;   /**< @brief 流表规则索引*/
struct rule_table table = {0,0,{0}};	/**< @brief 软件流表对象申明*/
struct fast_rule zero_rule = {0};		/**< @brief 定义一条空的流表项，用做和空规则对比*/


/**
* @brief 16网络序字节转换为硬件流表规则序
*
* @param n  ：网络字节序
*
* @return   返回16位的硬件流表规则序
*/
u16 n2rule16(u16 n)
{
	return htons(1) == 1 ? htole16(n):n;
}

/**
* @brief 32网络序字节转换为硬件流表规则序
*
* @param n  ：网络字节序
*
* @return   返回32位的硬件流表规则序
*/
u32 n2rule32(u32 n)
{
	return htons(1) == 1 ? htole32(n):n;
}

/**
* @brief 64网络序字节转换为硬件流表规则序
*
* @param n  ：网络字节序
*
* @return   返回64位的硬件流表规则序
*/
u64 n2rule64(u64 n)
{
	return htons(1) == 1 ? htole64(n):n;
}

/**
* @brief 将16进制的数字转化为规则的MAC地址顺序
*
* @param mac	：存储MAC地址的指针
* @param value  ：输入的MAC地址数字
*/
void set_rule_mac64(char *mac,u64 value)
{
	if(htons(1) == 1)
	{
		int i = 0;
		u64 v = value;
		for(;i<6;i++)
		{
			mac[i] = v & 0xFF;
			v >>= 8;
		}			
	}
	else
	{
		memcpy(mac,&value,6);
	}
}


/**
* @brief 将OF协议中OXM对象转化为规则的MAC地址序列
*
* @param mac	：存储MAC地址的指针
* @param oxm	：OF协议数据中的OXM对象
*/
void set_rule_mac_oxm(char *mac,char *oxm)/*OXM是网络序*/
{
	int i = 0;
	for(;i<6;i++)
		mac[i] = oxm[5-i];	
}

/**
* @brief 将OF协议中OXM对象转化为规则的IPv6地址序列
*
* @param ipv6   ：存储IPv6地址的指针
* @param oxm	：OF协议数据中的OXM对象
*/
void set_rule_ipv6_oxm(char *ipv6,char *oxm)/*OXM是网络序*/
{
	int i = 0;
	for(;i<16;i++)
		ipv6[i] = oxm[15-i];	
}

/**
* @brief 将OXM对象转化为规则存储序列
*
* @param dst	：存储规则序列的指针
* @param oxm	：将要被转化的OXM对象
* @param len	：转化的数据字节长度
*/
void oxm2rule(char *dst,char *oxm,int len)
{
	int i = 0;
	for(;i<len;i++)
		dst[i] = oxm[len-1 - i];	
}

/**
* @brief OpenBox设备硬件规则寄存的读操作函数
*
* @param regaddr	：读操作的寄存器地址
*
* @return   返回该寄存器对应的值
 * @note 读规则寄存器操作为间接寄存器操作，先要将访问的寄存器地址写入读寄存器地址中，写入值的高32位表示真实寄存器值，
 * 然后再从读寄存器的数据返回寄存器中读取该真实寄存器对应的值
*/
u64 openbox_rule_reg_rd(u64 addr)
{
#ifdef OpenBoxS28
	fast_reg_wr(FAST_RULE_REG_RADDR,(u64)addr<<32);
	return fast_reg_rd(FAST_RULE_REG_VADDR);
#else
	return fast_GME_reg_rd(addr);
#endif
}

/**
* @brief OpenBox设备硬件规则寄存的写操作函数
*
* @param addr   ：写操作的寄存器地址
* @param value  ：写操作的寄存器值
 * @note 写规则寄存器操作为间接寄存器操作，真实寄存器值存储在写入数值的高32位，对应此寄存器的值存放在低32位，
 * 将二者合并成为一个64位数据，写入规则间接写寄存器地址中，实现规则寄存器的间接访问操作
*/
void openbox_rule_reg_wr(u32 addr,u32 value)
{	
#ifdef OpenBoxS28
	fast_reg_wr(FAST_RULE_REG_WADDR,(u64)addr<<32|value);//原来使用的规则写法，正常	
#else
	fast_GME_reg_wr(addr,value);//原来使用的规则写法，正常
#endif
}

/**
* @brief OpenBox的动作命令寄存器读操作
*
* @param addr   ：读动作寄存器地址
*   
* @return	   返回该动作寄存地址的值
* @note 动作寄存器可直接使用定义的偏移地址进行访问，在实现函数中已经增加了动作寄存器的基地址偏移\n
 * 动作寄存器有效位宽只有32位，故只取返回值的低32位
*/
/*写动作寄存器*/
u32 openbox_action_reg_rd(u32 addr)
{
	return 0xFFFFFFFF & fast_reg_rd(FAST_ACTION_REG_ADDR + addr);
}

/**
* @brief OpenBox的动作命令寄存器写操作
*
* @param addr   ：写动作寄存器地址
* @param value  ：写动作寄存器的值
*/
/*写动作寄存器*/
void openbox_action_reg_wr(u32 addr,u32 value)
{
	fast_reg_wr(FAST_ACTION_REG_ADDR + addr,value);
}

/**
* @brief 写入一条规则到标准查表引擎
*
 * 往硬件写入一条指定的规则,输入参数为规则索引号和规则有效位，标准查表引擎是指顺序匹配查表
* @param idx		：写入规则的索引
* @param valid		：写入规则的有效位
 * @note 若将规则置无效，只需要将有效位标志置0即可
*/
/**/
void write_rule_normal(int idx,u32 valid)
{
	struct reg_value *value = (struct reg_value *)&table.rules[idx];//将规则转化为32位操作的数据形式
	int i = 0,cnt = sizeof(struct flow)*2/sizeof(struct reg_value);//cnt计算一条规则要写入多个少32位的值
	//写一条指定的规则数据到指定的位置
	table.rules[idx].valid = valid;	
	
	if(valid == 0)
	{
		table.rules[idx] = zero_rule;/*将规则清零，防止后续查询时还存在*/
		openbox_action_reg_wr(idx*8,0);
		goto delete_rule;/*删除规则或将规则置无效，仅写完此字段即可*/
	}
	
	/*写此条规则对应的ACTION*/
	openbox_action_reg_wr(idx*8,table.rules[idx].action);

	for(;i<cnt;i++)/*只写key和mask的值*/
	{
		openbox_rule_reg_wr(RULE_LEN*idx + i*sizeof(struct reg_value),(value->v[i]));//前一个计算规则开始的相对位置，后一个为此位置要写入的值
	}
	
	/*写入规则的优先级*/
	openbox_rule_reg_wr(RULE_LEN*idx + cnt*sizeof(table.rules[idx].priority),table.rules[idx].priority);
delete_rule:
	/*写入规则的有效位*/
	openbox_rule_reg_wr(RULE_LEN*idx + (cnt+1)*sizeof(table.rules[idx].valid),table.rules[idx].valid);	
}

/**
* @brief 写硬件规则操作函数
*
* @param idx	：规则索引
* @param valid  ：规则有效位
*/
void write_rule(int idx,u32 valid)
{
	write_rule_normal(idx,valid);
}



int cmp_key32(struct flow *rule,struct flow *key,struct flow *mask)
{
	u32 *m1 = (u32 *)rule;
	u32 *m2 = (u32 *)key;
	u32 *m3 = (u32 *)mask;
	u32 diffs = 0;
	int i = 0,cnt = sizeof(struct flow)/4;

	while(i<cnt && diffs == 0)
	{
		diffs |= (m1[i] ^ m2[i])&m3[i];	
		//printf("[%d]rule:%08lX,mask:%08lX,key:%08lX,diffs:%08lX\n",i,m1[i],m3[i],m2[i],diffs);
		i++;
	}
	//printf("-----------------diffs:%lX---------------\n",diffs);
	return diffs == 0;
}

int cmp_key(struct flow *rule,struct flow *key,struct flow *mask)
{
	u64 *m1 = (u64 *)rule;
	u64 *m2 = (u64 *)key;
	u64 *m3 = (u64 *)mask;
	u64 diffs = 0;
	int i = 0,cnt = sizeof(struct flow)/8;

	while(i<cnt && diffs == 0)
	{
		diffs |= (m1[i] ^ m2[i])&m3[i];	
		//printf("[%d]rule:%016lX,mask:%016lX,key:%016lX,diffs:%016lX\n",i,m1[i],m3[i],m2[i],diffs);
		i++;
	}
	//printf("-----------------diffs:%lX\n",diffs);
	return diffs == 0;
}

u32 fast_match_rule(struct flow *key)
{
	int i = 0;

	for(i=0;i<FAST_RULE_CNT;i++)/*MD5值为16字节*/
	{
		if(table.rules[i].valid == 1 && cmp_key32(&table.rules[i].key,key,&table.rules[i].mask))
		{
			key->ttl = i;
			return table.rules[i].action;/*返回该表项的Action*/
		}
	}
	return 0xFFFFFFFF;/*表示不命中或无动作*/
}

/**
* @brief 判断一条规则是否已经存在
*
* @param rule   ：输入判断的规则
*
* @return   -1:表示规则不存在\n
 *			其他，表示该规则存在，并返回其对应索引值
*/
/*
 * 判断规则是否已经存在,根据规则的MD5计算值比较,MD5计算是根据key+mask+priority三个字段计算的
 */
int rule_exists(struct fast_rule *rule)
{
	int i = 0;
	for(i=0;i<FAST_RULE_CNT;i++)/*MD5值为16字节*/
	{
		if(table.rules[i].valid == 1 &&
		   table.rules[i].md5[0] == rule->md5[0] &&
		   table.rules[i].md5[1] == rule->md5[1] &&
		   table.rules[i].md5[2] == rule->md5[2] &&
		   table.rules[i].md5[3] == rule->md5[3] 
		   )
			return i;
	}
	return -1;/*表示不存在，存在返回表的索引*/
}

/**
* @brief 试探性添加规则操作
*
* @param rule   ：需要添加的规则
* @param idx	：存储添加规则后的索引
*
* @return   -1：表示规则添加失败\n
 *			其他，表示添加规则后存储位置的索引
 * @note 该函数为是添加规则寻找一个可用的索引位置，如果存在规则，返回其索引，可用于更新；对于不存在规则，可找到一个可用位置存储规则
*/
int rule_exists_add(struct fast_rule *rule,int *idx)
{
	int i = 0;
	for(i=0;i<FAST_RULE_CNT;i++)/*MD5值为16字节*/
	{
		if(table.rules[i].valid == 1)
		{
			if(table.rules[i].md5[0] == rule->md5[0] &&
			   table.rules[i].md5[1] == rule->md5[1] &&
			   table.rules[i].md5[2] == rule->md5[2] &&
			   table.rules[i].md5[3] == rule->md5[3] 
			   )
				return i;
		}
		else if(*idx == -1)
		{
			*idx = i;/*记录第一个可用规则位置*/			
		}
	}
	return -1;/*表示不存在，存在返回表的索引*/
}
/**
* @brief 添加规则操作
*
* @param rule   需要添加的规则
*
* @return   -1：表示规则添加失败\n
 *			-E_RULE_INDEX_OVERFLOW：表示规则已经满了\n
 *			其他，表示添加规则后的索引
*/
/*新增一条规则,要求用户输入完整的规则数据结构,包括规则字段,掩码和相应动作 
 * 返回值为存储当前规则的索引值
 */
int fast_add_rule(struct fast_rule *rule)
{
	int idx = -1,ret = -1;
	if((ret=rule_exists_add(rule,&idx)) == -1)
	{
		if(idx != -1)
		{
			printf("wirte: %d\n", idx);
			table.rules[idx] = *rule;//将用户规则存入当前索引的规则位置		
			table.cnt++;//规则数目增加一条
			write_rule(idx,1);/*将此规则写入硬件,将规则置为有效状态*/
			ret = idx;
		}
		else
		{
			printf("wirte failed: %d\n", idx);
			return -E_RULE_INDEX_OVERFLOW;
		}
	}
	
	return idx;//返回当前规则索引
}


/**
* @brief 修改规则操作
*
* @param rule   新的规则内容
* @param idx	要修改的规则索引
*
* @return   -E_RULE_INDEX_OVERFLOW：表示规则不存在\n
 *			返回输入idx的值，表示修改此索引规则成功
*/
/*修改一条指定位置的规则
 * 返回值与修改索引相等表示修改成功,其他值表示修改失败
 */
int fast_modify_rule(struct fast_rule *rule,int idx)
{
	if(idx >= 0 && idx < FAST_RULE_CNT)
	{
		table.rules[idx] = *rule;//将用户规则存入当前索引的规则位置		
		write_rule(idx,1);//将此规则重新写入硬件,将规则置为有效状态*/
		return idx;
	}
	return -E_RULE_INDEX_OVERFLOW;
}

/**
* @brief 删除一条规则
*
* @param idx	：删除规则的索引
*
* @return   -E_RULE_INDEX_OVERFLOW：表示规则不存在\n
 *			返回输入idx的值，表示删除此索引规则成功
*/
/*删除一条指定的规则 
 * 返回值与删除索引相等表示删除成功,其他值表示删除失败
 */
int fast_del_rule(int idx)
{
	if(idx >= 0 && idx < FAST_RULE_CNT)
	{
		table.rules[idx] = zero_rule;//将零规则存入当前索引的规则位置		
		write_rule(idx,0);//将此规则重新写入硬件,简化实现方式可以只更新规则的有效标志位
		return idx;
	}
	return -E_RULE_INDEX_OVERFLOW;
}

/**
* @brief 打印软件缓存的规则数据
 * 
 * @warning 仅在当前操作规则的进程中打印有效
*/
void print_sw_rule(void)
{
	u32 i = 0,j = 0,cnt = sizeof(struct flow)*2/sizeof(struct reg_value) + 3;/*3指优先级、有效位和动作*/	
	struct reg_value *value;

	printf("--------------------------------xxx----------------------------------\n");
	for(i=0;i<FAST_RULE_CNT;i++)
	{
		print_sw_rule_by_idx(i);
	}
	printf("--------------------------------xxx----------------------------------\n");
}

void print_sw_rule_by_idx(int idx)
{
	u32 j = 0,cnt = sizeof(struct flow)*2/sizeof(struct reg_value) + 3;/*3指优先级、有效位和动作*/	
	struct reg_value *value;

	value = (struct reg_value *)&table.rules[idx];
	printf("0x%04X  ",idx);
	for(j=0;j<cnt*4;j++)
	{
		printf("%02X",*((u8 *)value+j));
		if(j % 64 == 63)printf("\n--------");
	}
	printf("\n");
}

void print_user_rule(struct fast_rule *rule)
{
	u32 j = 0,cnt = sizeof(struct flow)*2/sizeof(struct reg_value) + 3;/*3指优先级、有效位和动作*/	
	struct reg_value *value;

	value = (struct reg_value *)rule;
	printf("0x%04X  ",0);
	for(j=0;j<cnt*4;j++)
	{
		printf("%02X",*((u8 *)value+j));
		if(j % 64 == 63)printf("\n--------");
	}
	printf("\n");
}

/**
* @brief 打印硬件流表的所有规则条目
 * 
 * 打印硬件规则，将重新从硬件的规则空间重新读取所有规则数据，重新拼装为规则数据结构进行打印输出
*/
/*打印硬件存储的规则数据,每个数据都需要从硬件寄存器读返回*/
void print_hw_rule(void)
{
	u32 i = 0,j = 0,cnt = sizeof(struct flow)*2/sizeof(struct reg_value) + 2;	/*2指优先级和有效位，动作要单独读*/
	u32 value = 0;

	printf("-----------------Default Action:0x%X-----------------------------\n",openbox_action_reg_rd(FAST_DEFAULT_RULE_ADDR));
for(;i<FAST_RULE_CNT;i++)
	{
		printf("0x%04X  ",i);
		for(j=0;j<cnt;j++)
		{
			value = 0xFFFFFFFF & openbox_rule_reg_rd(RULE_LEN*i + j*4);
			printf("%08X ",be32toh(value));
			if(j % 16 == 15)printf("\n--------");
		}
		printf("Action:0x%X",openbox_action_reg_rd(i*8));
		printf("\n");		
	}
	printf("-----------------Default Action:0x%X-----------------------------\n",openbox_action_reg_rd(FAST_DEFAULT_RULE_ADDR));
}

/**
* @brief 读取一条指定的硬件规则条目
*
* @param rule   ：读取规则后存储规则的指针
* @param index  ：读取规则的索引值
*
* @return 
*/
/*从硬件读取一条指定的规则数据,数据存储在用户输入的rule数据结构中
 * 返回值与读规则索引相等表示读成功,其他值表示读取失败
 */
int read_hw_rule(struct fast_rule *rule,int index)
{	
	if(index < 0 || index > FAST_RULE_CNT-1)
	{
		printf("index Error!\n");
		return -1;
	}
	else
	{
		int j = 0,cnt = sizeof(struct flow)*2/sizeof(struct reg_value) + 3;/*3指优先级、有效位和动作*/
		struct reg_value *value = (struct reg_value *)rule;
		for(j=0;j<cnt;j++)
		{
			value->v[j] = be32toh(0xFFFFFFFF & openbox_rule_reg_rd(RULE_LEN*index + j*4));
		}
		return index;
	}
}

/**
* @brief 初始化硬件流表规则
 * 
 * 主要是将硬件流表规则清空，并写入默认的动作操作指令
*
* @param default_action ：匹配不了所有规则后，执行的动作指令
*/
void init_rule(u32 default_action)
{
	u32 i = 0,j = 0,cnt = sizeof(struct flow)*2/sizeof(struct reg_value) + 2;/*2指优先级和有效位*/

	memset(&table,0,sizeof(struct rule_table));
	memset(&zero_rule,0,sizeof(struct fast_rule));
	//给硬件配置默认规则	
	openbox_action_reg_wr(FAST_DEFAULT_RULE_ADDR,default_action);
	FAST_DBG("librule version:%s,Default Action:0x%X\n",RULE_VERSION,default_action);
}
