# Mastik：微体系结构侧信道攻击工具包

## 1. 引言

微体系结构侧通道攻击利用了处理器内部组件的竞争，从而泄漏了进程之间的信息。虽然从理论上讲这类攻击很简单，但实际的实现方式往往很复杂，并且需要对文献记载不充分的处理器函数和其他领域专有的知识有充分的了解。因此，进入微体系结构侧通道攻击的工作存在障碍，这阻碍了该领域的发展以及现有软件抵御此类攻击的能力的分析。

本文介绍 Mastik，一个用于测试微体系结构侧通道攻击的工具包。Mastik旨在提供已发布的攻击和分析技术的实现。在撰写本文时，Mastik尚处于 开发的早期阶段。0.02版的代号 “Aye Aye Cap'n” ，目前已发布。

该版本包括在Intel x86-64体系结构上实施六种基于缓存的攻击。其中包括对L1数据缓存的Prime + Probe攻击，L1指令缓存上的Prime + Probe，LLC上的Prime + Probe，FLUSH + RELOAD，FLUSH + FLUSH和性能降低攻击。

除了实施攻击之外，Mastik还提供了一些促进攻击的工具。这些函数包括用于处理符号代码引用的函数，例如加载程序符号名称或调试信息，以及简化侧通道攻击中常用的某些系统函数的函数。0.02版中的新内容是FR-trace实体程序，它支持从命令行安装Flush + Reload攻击。

现在，我们用一些例子来说明Mastik的好处( <font color="red">第二节</font> )，然后进行更详细的介绍 接口说明( <font color="red">第三节</font> )。



## 2. Mastik示例

为了展示Mastik的强大函数，我们现在展示如何在GnuPG 1.4.13上重现Flush + Reload攻击。GnuPG 1.4.13使用平方和乘法算法，用于执行RSA解密和签名的模幂运算步骤。Yarom和Falkner证明此实现容易受到Flush + Reload边信道攻击的攻击。他们使用Flush + Reload跟踪受害者对乘法、平方和模块化归约运算的使用。从跟踪的操作中，攻击者可以恢复与受害者的私钥相对应 的指数位。

尽管“FLUSH + RELOAD”攻击的核心相对简单，但是攻击的实现需要以固定的间隔重复探测内存。当被操作系统中断时，它还应该能够与受害者重新同步。此外，攻击者需要能够将源代码位置转换为内存地址。Mastik负责大部分此类操作。它隐藏了复杂性，并为用户提供了一个用于发起攻击的简单接口。
<font color="red">Listing 1</font> 显示了攻击的执行情况 (类似的实现程序在Mastik发行版的 demo/FR-gnupg-1.4.13.c 中)。Mastik使用非透明句柄类型 fr_t 抽象攻击。攻击句柄通过调用来实例化 fr_prepare() ( <font color="red">第9行</font> )。11 至 18行 设置攻击监视的内存位置。和Yarom和Falkner一样 ，我们将攻击设置为监视代码中计算乘法、平方和模块化归约运算的位置。为了指定这些位置，我们使用对受害者源代码行的引用( <font color="red">第5行</font> )。sym_getsymboloffset() 使用GnuPG二进制文件中的调试信息将这些引用转换为二进制文 件中的偏移量。我们使用 map_offset() 函数将这些偏移量映射到间谍程序的地址空间，并且 fr_monitor() 设置“FLUSH + RELOAD”攻击以监视这些位置。

<center>Listing 1. Flush Reload attack on GnuPG 1.4.13</center>

```c
1 	#define SAMPLES 100000
2 	#define SLOT 2000
3 	#define THRESHOLD 100
4
5		char *monitor[] = { "mpih−mul.c:85", "mpih−mul.c:271", "mpih−div.c:356" };
6 	int nmonitor = sizeof (monitor)/ sizeof (monitor [0]);
7
8		int main(int ac, char **av) {
9 	fr_t fr = fr_prepare ();
10
11 	for ( int i = 0; i < nmonitor; i++) {
12 			uint64_t offset = sym_getsymboloffset(av [1], monitor[i ]);
13 			if ( offset == ~0ULL) {
14 					fprintf ( stderr , "Cannot find %s in %s\n", monitor[i], av [1]);
15 					exit (1);
16 			}
17 			fr_monitor ( fr , map_offset(av [1], offset ));
18 	}
19
20 	uint16_t *res = malloc(SAMPLES * nmonitor * sizeof(uint16_t));
21 	bzero( res , SAMPLES * nmonitor * sizeof(uint16_t));
22 	fr_probe( fr , res );
23
24 	int l = fr_trace ( fr , SAMPLES, res, SLOT, THRESHOLD, 500);
25 	for ( int i = 0; i < l ; i++) {
26 			for ( int j = 0; j < nmonitor; j++)
27 					printf ("%d ", res[ i * nmonitor + j ]);
28 					putchar( ' \n' );
29 			}
30 	}
```

攻击本身是在 <font color="red">24行</font> 。fr_trace() 函数在其监视的任何内存位置中等待活动。然后，它以固定的时间间隔收集活动记录。当检测到足够长时间的不活动状态或函数空间不足以存储结果时，收集将停止。这些活动记录了从受监视位置读取数据所花费的时间。较短的访问时间表明该位置已缓存，因此处于活动状态。

在终止之前，程序将输出结果。程序输出的一部分显示在 图1 。如图所示，每个受监视位置都有明确的活动区域。根据这些信息，攻击者可以重构受害者执行的操作顺序并推断出指数。

<center>图1</center> 

![](https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200817093915.png)

如我们所见，Mastik为攻击提供了易于使用的接口。它隐藏了大多数攻击实施细节，仅公开了针对特定受害者所需的那些参数。 现在，我们将描述Mastik在抽象各种攻击时采用的一些模式。



## 3. API设计

设计用于侧信道攻击的API的挑战之一是在三个冲突的目标之间取得平衡。我们希望接口简单统一，同时，我们想发挥出每种攻击独特的优势。另外，我们希望接口的实现尽可能优化，以最大程度地减少攻击足迹。

Mastik通过为所有攻击提供类似的接口来实现这种平衡，而无需提供基础操作的共享实现。因此，攻击接口具有相同的外观，但是接口中存在针对某种特定攻击的变化，并且在不同攻击中用于相似目的的接口类型不具有相同的超类型。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200817094006.png" style="zoom:50%;" />

Mastik中的每次攻击都使用一个攻击描述符进行封装， 它是指向描述攻击信息的结构体的不透明指针，以及管理该结构体和实施攻击的一组函数。 表格1 总结实现了的攻击、描述符类型和用于攻击函数的前缀。将来，我们希望某些攻击会共享描述符。例如，Evict + Reload 可以使用LLC Prime + Probe描述符( l3pp_t)。 对于每种攻击，Mastik提供三种函数: 描述符管理，攻击设置和攻击。

1. **描述符管理** 初始化函数 XX_prepare() (XX 是攻击前缀) 初始化描述符。对于某些描述符类型，可能需要一个为初始化例程提供参数的参数。 当前，只有LLC Prime + Probe接受参数。通过 NULL 选择默认行为。XX_release() 函数释放描述符及其分配的所有资源。

2. **攻击设定** 每种攻击都定义了一个攻击空间，其中包含一组该攻击可以操作的指针。对于大多数攻击，操作是 监控 此指针位置的活动。指针的属性和攻击相关。在Flush + Reload攻击中，一个指针是运行攻击的进程的虚拟地址空间中的地址。对于Prime + Probe攻击，这些指针标识目标缓存中的集合。对于每种攻击，Mastik提供了几种函数来管理使用描述符描述的攻击所探测的指针集。这些函数是:
   
- **XX_monitor()** 向描述符监视的一组指针中添加一个指针。
   
   -  **XX_unmonitor()** 从描述符监视的点集中删除一个指针。 
   - **XX_monitorall()** 将所有可能的指针添加到描述符监视的指针集。仅支持L1攻击。
   - **XX_unmonitorall()** 从描述符监视的指针集中删除所有点。 
   - **XX_getmonitoredset()** 返回描述符监视的指针集。
	- **XX_randomise()** 使用非安全的伪随机数生成器对受监视指针的集合进行重新排序。
	
	初始化L1攻击描述符会按随机顺序监视所有指针(缓存集)。初始化其他描述符以不监视任何指针。
	
3. **攻击** 攻击阶段，由 XX_probe()实现， 包括探测每个监视指针以确定是否活动。典型的结果是一组定时数据，用于测量探测每个指针的时钟周期数。结果与XX_getmonitoredset() 返回的探针的顺序匹配。 两次攻击的结果含义不同。有关更多信息，请参见源文件。

4. **攻击变化** Prime + Probe攻击通常受益于双向探测。对于L1 Data和LLC Prime + Probe攻击，Mastik提供了函数 XX_bprobe()， 该函数沿相反的方向执行探测。对于LLC攻击，通常是计算缓存未命中的次数而不是探测缓存集的总时间。函数 l3_probecount() 和 l3_bprobecount() 执行此操作。

5. **反复攻击** 通常，单次探测能提供的信息太少。函数 XX_repeatedprobe() 执行一系列的探测，如果环境支持XX_bprobe()，该函数会交替使用 XX_probe() 和 XX_bprobe()，否则，只是用XX_probe() 。该函数的 *slot* 参数可管理探测行为，使其在每 *slot* 个周期内执行一次探测。如果错过了一个 *slot*，则该 *slot* 中各点的计时结果将设置为0。(对于probecount版本 ，其结果将设置为〜0)
    
6. **痕迹** Flush + Reload和Flush + Flush攻击支持重复攻击的扩展版本。这个版本中，XX_trace() 等待受监视的缓存行中的活动。数据收集在检测到活动时开始，并在不再检测到活动或存储结果的空间用尽时停止。

7. **性能下降攻击** 与其他攻击不同，性能降低攻击不会监视受害者。相反，它针对目标受害者经常使用的缓存行，并将其从缓存中逐出。为了反映是不同的用途 ，使用函数 *target* 代替 *monitor* 发起攻击。 例如函数pda_target() 将目标添加到性能下降攻击的目标列表中。函数 pda_activate() 和 pda_deactivate() 开始和停止攻击。 pda_activate() 产生执行攻击的子进程。 pda_deactivate() 杀死子进程。

8. **符号管理** Mastik提供了三种将符号转换为文件偏移量的函数。 sym_loadersymboloffset() 在加载程序符号表中找到一个符号。 sym_debuglineoffset() 找到对应于特定源代码行的机器代码。在Linux中，这些功能依赖于 libbfd，libdwarf 和 libelf。 要使用，请确保 libdwarf-devel 和 binutils-devel( 或者 libdwarf-dev，binutils-dev 和 libelf-dev) 已安装。

    sym_getsymboloffset() 提供了用于将符号引用转换为文件偏移量的通用接口。它可以识别四种输入格式：文件偏移，虚拟地址，装载程序符号 和行号。它可以进一步识别允许偏移的简单算术运算。例如，输入“ main + 0x40“ 指 *main* 函数开始后64字节的位置。

9. **实用功能** map_offset() 将文件映射到进程的虚拟地址，并以文件中指定的偏移量返回指向数据的指针。仅映射包含指定偏移量的页面。 unmap_offset() 删除映射。delayloop() 执行多个周期的繁忙循环。如果XX_repeatedprobe() 没有提供所需的功能，可以在每次探测之间使用 delayloop() 函数。delayloop() 的另一种用途是为了生成足够的活动以避免CPU频率缩放。根据我们的经验， delayloop (3000000000U) 总是能达到预期的效果。但对你来说，可能会不同。



> 原文：https://cs.adelaide.edu.au/~yval/Mastik/Mastik.pdf
>
> Mastik主页：https://cs.adelaide.edu.au/~yval/Mastik/

