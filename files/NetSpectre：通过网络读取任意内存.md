# NetSpectre：通过网络读取任意内存

## 摘要

推测执行是现代处理器能够实现高性能的一个关键因素。在推测执行过程中，处理器可能会执行程序一般不会执行到的操作。如果推测执行被中止，这些操作对体系结构的影响和结果会被丢弃，但对微架构的影响可能会保留下来。最近公布的Spectre攻击就是利用这些保留下来的微架构状态来读取其他程序的内存内容。然而，Spectre攻击需要在目标系统上进行某种形式的本地代码执行。因此，只要攻击者无法在目标机器运行任何代码，该系统就被认为是安全的。

在本文中，我们介绍了NetSpectre，一种通用的远程Spectre变种1攻击。为此，我们展示了第一个通过网络进行的远程Evict+Reload缓存攻击，每小时能泄露15bits数据。除了将现有的攻击在网络场景进行实现，我们还演示了第一个不使用缓存隐蔽信道的Spectre攻击。相反，我们提出了一种新型的基于AVX的高性能隐蔽信道，并且在无缓存的Spectre攻击中使用了这种隐蔽信道。我们的实验表明，在实际中，基于AVX的隐蔽信道的远程Spectre攻击效果有明显提升，每小时能从目标系统泄漏60bits数据。我们验证了NetSpectre攻击可以在局域网以及谷歌云的虚拟机之间工作。

NetSpectre标志着攻击模式从本地到远程的转变，使得更多设备受到Spectre攻击。现在，还必须在不运行任何可能由攻击者控制的代码的设备上考虑Spectre攻击。我们证实，特别是在这种远程情况下，基于较弱小工具的攻击（不会泄漏实际数据）仍然非常有效，可以远程破坏地址空间布局随机性。我们讨论的几个Spectre小工具比预期的功能更多，特别是我们设计的value-thresholding技术，它可以在没有典型的位选择机制的情况下泄露一个秘密值。我们概述了未来对Spectre攻击和缓解措施研究的挑战。



## 1. 导言

现代计算机在性能上进行了高度优化，然而，这些优化通常都会造成微架构状态改变。侧信道攻击会观察这些保留下来的状态改变，并由此推断出攻击者通常无法获取到的信息。基于软件的侧信道攻击尤其令人不安，因为它们不需要访问物理设备。 这些攻击中的许多攻击都属于微体系结构攻击类别，它们利用由微体系结构要素引起的时间或行为方面的差异。

在过去的20年中，基于软件的微体系结构攻击已从对密码算法实现的理论攻击演变为更通用的实际攻击，最近演变为破坏内存和进程隔离的潜在威胁。Spectre是一种针对微体系结构的攻击，它诱使另一个程序以推测方式执行指令序列，留下对微架构的状态改变。 在迄今为止展示的所有Spectre攻击中，这些状态改变是由于数据缓存（即传统的缓存隐蔽信道）污染造成的时间差异。

在Spectre攻击中被使用的推测执行是现代处理器能够实现高性能的关键。现代处理器中的分支预测单元会做出合理的猜测，即选择哪个分支，然后处理器按照分支的预测方向有选择地执行预期的指令序列。通过操纵分支预测，Spectre可以诱骗目标进程执行一系列的内存访问，这些访问将机密从选定的虚拟内存位置泄露给攻击者。 这完全破坏了机密性，并使受影响系统上的几乎所有安全机制失效。 Spectre变种1是影响大量设备的一个变种，主要与边界检查后的错误推测有关，攻击者首先执行诸如边界检查之类的操作，然后执行会对微体系结构状态造成影响的代码片段，这些代码片段被称为“ Spectre 小工具”。

到目前为止，Spectre攻击已经在JavaScript和本地代码中得到了证实，但是，任何允许时序测量足够准确的环境以及某种形式的代码执行都可能导致这些攻击。对Intel SGX 飞地（enclaves）的攻击表明，飞地（enclaves）也容易受到Spectre攻击。然而，有数十亿的设备从未运行过任何攻击者控制的代码，包括JavaScript、本地代码，也没有在目标系统上执行其他形式的代码。目前，这些系统被认为是安全的，可以抵御这些Spectre攻击。事实上，厂商们都确信这些系统仍然是安全的，并建议不对这些设备采取任何行动。

在本文中，我们介绍了NetSpectre，一种基于Spectre变种1的新攻击，不需要攻击者控制目标设备上的代码，从而影响数十亿设备。与本地的Spectre攻击类似，我们的远程攻击需要在目标设备的代码中存在Spectre 小工具。我们表明，在暴露的网络接口或API中包含所需Spectre 小工具的系统可以通过我们的远程Spectre攻击进行攻击，并允许攻击者通过网络读取任意内存。攻击者只需要向受害者发送一系列的请求，并测量响应时间，就可以从受害者的内存中泄露一个秘密值。

我们表明，一般来说，内存访问延迟可以从网络请求的延迟中反映出来。因此，我们证实了攻击者有可能通过对更多的测量值进行处理和求平均值来远程区分特定缓存行上的缓存命中和未命中。基于这一点，我们实现了第一个基于访问的远程缓存攻击，Evict+Reload的远程攻击变体，称为*Thrash+Reload*。我们的远程*Thrash+Reload*攻击是之前对加密算法的远程缓存定时攻击的一个重大飞跃。我们推进了这项技术，将现有的Spectre攻击应用到网络的环境中。这种NetSpectre变种能够从包含漏洞的目标系统中每小时泄露15比特。

通过利用以前未知的基于AVX2指令执行时间的侧信道，我们还演示了第一个完全不依赖缓存隐蔽信道的Spectre攻击。我们基于AVX的隐蔽信道在0.58%的错误率下实现了每秒125字节的本机代码性能。通过在我们的NetSpectre攻击中使用这种隐蔽信道而不是缓存隐蔽信道，我们实现了更高的性能。由于不再需要缓存驱逐，我们将局域网中目标系统的泄漏速度提高到每小时60比特。在谷歌云中，我们可以从另一个独立的虚拟机中每小时泄露3比特左右。

我们证实了使用以前被忽略的小工具可以在远程攻击中破解地址空间布局随机化。地址空间布局随机化(ASLR)是一种部署在当今大多数系统上的防御机制，几乎随机化了所有地址。由于ASLR的目的主要是防御远程攻击，而不是本地攻击，所以本地代码执行的攻击者可以很容易地绕过ASLR。因此，到目前为止，许多针对Spectre攻击的较弱的小工具都被忽略了，因为它们不允许泄露数据内容，而只是泄露地址信息。然而，在远程攻击场景下，这些较弱的小工具就变得非常强大。

Spectre小工具可以比之前工作中预期的更加灵活，这不仅在我们远程ASLR攻击中使用的较弱的小工具中表现得明显，而且在我们提出的值阈值（value-thresholding）技术上更明显。值阈值技术并没有使用经典的在以前的Spectre攻击中看到的位选择和内存引用机制，相反，值阈值技术直接利用比较中的信息泄漏，使用类似于二进制搜索的分治法。NetSpectre标志着从本地攻击到远程攻击的模式转变。

NetSpectre标志着从本地攻击向远程攻击的转变，这显著扩大了Spectre攻击的影响范围，并增加了受影响设备的数量。特别地，那些没运行不受信任攻击者控制的代码的设备也需要考虑是否存在Spectre安全威胁，这表明以前被认为安全的这些设备也必须采取措施。 我们提出了一种有更清晰结构的替代品Retpolines。 未来对Spectre攻击和修复的研究面临着一系列挑战，即：当前的防御措施只能是临时的解决方案，因为它们只能解决表面问题，而不能解决根本问题。

本文的贡献是：

1. 我们介绍了NetSpectre，一个通用的远程Spectre变种1攻击。为此，我们展示了第一个通过网络访问实现的远程缓存攻击（Evict+Reload），作为NetSpectre的构建模块。

2. 我们展示了第一个不利用缓存的Spectre攻击。取而代之的是，我们提出了一种新的基于AVX的高性能隐蔽通道，它极大地提高了远程Spectre攻击的性能。

3. 我们表明，即使是较弱的本地Spectre攻击小工具，无法泄露实际数据，但在远程Spectre攻击中仍然非常强大，可以在设备上不执行任何代码的情况下远程破解ASLR机制。

4. 我们表明，Spectre小工具可以比预期更通用。我们的 *值-阈值技术* 允许获取一个秘密值，而无需典型的位选择和内存参考机制。

本文的其余部分组织如下。在第2节中，我们提供了关于推测执行和微架构攻击的背景。在第3节中，我们提供了NetSpectre攻击的完整概述。在第4节中，我们展示了如何构建用于NetSpectre攻击的远程微架构隐蔽信道。在第5节中，我们展示了如何将这些构件组合起来，通过网络提取内存内容。在第6节中，我们评估了我们攻击的性能。在第7节中，我们讨论了针对本地和基于网络的Spectre攻击的对策，并概述了未来研究的挑战。在第8节中，我们进行了总结。



## 2. 背景资料

在本节中，我们将讨论乱序执行和乱序执行的一个子集：推测执行。我们详细介绍了分支预测，这是大多数推测执行。最后，我们将讨论已知的微体系结构侧信道攻击以及我们在用例中使用的更好的方案：SIMD指令。



### 2.1 乱序执行和推测执行

现代处理器并不是严格地一条指令接一条指令地执行，而是有多个执行单元并行运行，串行指令流分布在这些执行单元上，从而使空闲的处理器资源减少。为了保留在架构上定义的执行顺序，处理器具有所谓的重排序缓冲区，该缓冲区可以对微操作进行缓冲（在架构级别上可见），直到它们执行完成后按照指令流定义的顺序返回。 因此，乱序执行使处理器可以预先计算指令执行的结果并对微架构状态产生影响。 像简单的流水线处理器一样，乱序执行处理器也会遭受中断的困扰，因为任何预先计算的结果和对微架构状态的改变都必须舍弃。 但是，这仅限于体系结构可见状态，微体系结构的状态可能会被改变。 预先计算但不淘汰的指令称为暂态指令。

现代处理器上的乱序执行通常可以在架构上可见的状态前运行几百条简单指令。实际数量取决于具体的指令和具体处理器上重排序缓冲区的大小。

几乎每一个复杂软件的指令流都不是纯线性的，而是包含（有条件的）分支。因此，处理器往往不能提前知道该执行分支的哪个方向，即不知道后续指令的运行顺序。在这种情况下，处理器使用预测机制来推测沿其中一条路径执行指令。因此，推测性执行是乱序执行的严格子集。正确的预测可以提高处理器的性能和效率。不正确的预测需要丢弃错误预测后的任何预先计算的结果和对微体系结构状态的影响。

### 2.2 分支预测

分支预测是最常见的预测机制，该机制导致推测执行。很自然，处理器的性能和效率会随着预测的质量而提高。因此，现代处理器集成了许多分支预测机制。

英特尔处理器有 "直接调用和跳转"、"间接调用和跳转 "和 "条件分支 "的预测机制。这些预测机制在不同的处理器组件中实现，例如，分支目标缓冲区（BTB）、分支历史缓冲区（BHB）和再转栈缓冲区（RSB） 。这些缓冲器可结合使用，以获得良好的预测效果。由于分支预测逻辑通常不在物理核之间共享，所以处理器只从同一核上以前的分支执行中学习。

### 2.3 微架构攻击

大多数微架构优化都依赖于处理后的数据或其位置。因此，观察优化的效果（例如，更快的执行时间）会泄露信息，例如，关于数据或其位置的信息。

传统上，微架构攻击分为两类：侧信道攻击，属于非破坏性攻击（被动）；故障攻击，属于破坏性攻击（主动）。侧信道攻击（Side-channel attacks）通常用于构建隐蔽信道，即连接双方通过侧信道进行通信。微架构侧信道攻击最早是针对密码算法的攻击进行探索的。最近，通用的实用攻击技术被开发出来，并被用于广泛的攻击目标，例如：Flush+Reload。

微架构攻击通常被认为是基于软件的攻击，与传统的侧通道攻击和需要物理访问设备的故障攻击不同。微架构故障攻击最突出的例子是Rowhammer，这是现代DRAM的一个硬件漏洞。Rowhammer使非特权攻击者能够修改特权DRAM内存位置。

Meltdown和Spectre是最近的两种微架构攻击。它们都使用隐蔽信道来传输秘密数据，但攻击本身并不是侧信道攻击。由于它们是非破坏性的，所以它们似乎不属于这两种类型。

Meltdown是一个存在于许多现代处理器中的漏洞。它是一系列攻击的基础，这些攻击都绕过了用户可访问页表位(对内核页设置为0)提供的隔离，例如，在Meltdown之前独立发现的针对KASLR的攻击。完整的Meltdown攻击允许攻击者读取任意内核内存。

幽灵攻击利用了大多数现代处理器中存在的推测执行机制。因此，它们并不依赖于任何漏洞，而仅仅依赖于优化策略。通过操纵分支预测机制，攻击者诱使受害者进程执行攻击者选择的代码小工具。这使得攻击者能够建立一个从受害者进程中的推测执行到攻击者控制的接收者进程的隐蔽信道。

### 2.4 缓存攻击

最重要的一类微架构攻击是缓存攻击。缓存攻击利用小的内存缓冲区（称为缓存）引入的时序差异。这些CPU缓存通过在小而快的处理器内存储器中缓冲经常使用的数据来降低内存访问延迟。现代CPU有多个缓存级别，这些缓存要么是每个核心的私有缓存，要么是跨核心共享的缓存。

缓存侧信道攻击是最早的微架构攻击。过去已经提出了不同的缓存攻击技术，包括Evict+Time、Prime+Probe和Flush+Reload。这些攻击的变种例如Evict+Reload，以及Flush+Flush。Flush+Reload攻击及其变种工作在缓存行粒度上，因为它们依赖于共享内存。共享内存中的任何缓存行都将是包含末级缓存中的共享缓存行。在Flush+Reload攻击中，攻击者不断刷新目标内存位置，并测量重新加载数据所需的时间，如果重载时间较低，攻击者就会得知另一个进程已经将缓存行加载到缓存中。各种Flush+Reload攻击已经被证实，例如，对加密算法、Web服务器函数调用、特定系统活动、用户输入和内核寻址信息的攻击。Prime+ Probe遵循类似的原理，但只有一个缓存集的粒度。它的工作原理是占用内存地址，并测量它们何时从缓存中被驱逐。因此，Prime+Probe攻击不需要任何共享内存。各种Prime+Probe攻击已经被证实，例如，对加密算法、用户输入和内核地址信息的攻击。

缓存时序侧信道在远程时序攻击中也得到了证实。Bernstein提出了一种针对AES算法简单实现的远程定时攻击。基本的时序差异是由算法中的内部冲突引起的，与之对应的是AES计算过程中缓存未命中的次数。随后，许多学者发表了一些改进和重现这种攻击的论文。

侧信道攻击的一个特殊用例是隐蔽信道。在隐蔽信道中，攻击者同时控制着触发侧信道状态变化的部分和测量侧信道状态的部分。这种攻击可以用来将信息从一个安全域泄露到另一个安全域，同时绕过任何存在于架构层面或以上的隔离。Prime+Probe和Flush+Reload都已经被用于高性能的隐蔽信道中。Meltdown和Spectre内部使用隐蔽信道将数据从瞬时状态转化为持久化状态。

### 2.5 SIMD指令

SIMD（单指令多数据）指令允许对多个数据值进行并行操作。SIMD指令作为指令集扩展可在多种现代处理器上使用，例如，英特尔MMX扩展、AMD 3DNow！扩展以及ARM VFP和NEON扩展。在英特尔上，一些SIMD指令由处理器内核内的专用SIMD单元处理。然而，为了避免浪费能源，SIMD单元在不使用时会被关闭。因此，要执行这类SIMD指令，首先要给SIMD单元上电，这会在前几条SIMD指令上引入一个小的延迟。Liu提到，一些SIMD指令可以用来改善总线竞争隐蔽信道，因为它们可以实现更直接地内存总线访问。然而，到目前为止，SIMD流指令还没有被用于纯SIMD隐蔽信道或侧信道攻击。

### 2.6 高级持续性威胁

现代硬件和软件的复杂性不断增加，这也现象也适用于恶意软件，特别是像Stuxnet、Duqu或Flame这样有针对性的恶意软件，已被证实是极难检测的，它们可以在目标系统或网络上持续存在数周或数月。因此，这种恶意软件也被称为 "高级持续性威胁"（APTs） 。在这种情况下，每天传输几比特到字节的慢速隐蔽信道（例如，气隙隐蔽信道）也是非常实用的，因为它们可能会运行很长时间。APTs通常是一组具体的利用组合，通过绕过不同的安全机制来实现一个总体目标。

### 2.7 地址空间布局随机化

现代操作系统中存在的一种安全机制是地址空间布局随机化（ASLR）。它随机化内存中对象或区域的位置，例如堆对象和栈，使攻击者无法预测正确的地址。从本质上讲，这是一种概率方法，但是在实践中它可以显著提高安全性。ASLR的主要目的是防御控制流劫持攻击，但它也使其他远程攻击变得困难，因为攻击者必须提供一个特定的地址。



## 3. 攻击概述

在本节中，我们用一个简单的例子来讲述NetSpectre攻击。NetSpectre攻击由两个NetSpectre小工具组成：一个泄密小工具和一个传输小工具。我们讨论了这两个小工具的作用，它们允许攻击者在不执行或访问任何本地代码的情况下进行Spectre攻击。我们根据NetSpectre小工具的类型（泄漏或传输）和它们所使用的微架构元素（如缓存）来详细讨论它们。

Spectre攻击会诱导受害者推测性地执行在程序指令严格序列化有序处理中不会发生的操作，这些操作会将受害者的机密信息通过隐蔽信道泄露给攻击者。Spectre的变体1通过错误地训练一个条件分支，如边界检查，诱导受害者进行推测性性执行。Spectre的变体2通过恶意注入地址到分支目标缓冲区，诱导受害者进行推测性性执行。虽然我们的方法可以利用任何Spectre变种，但我们专注于Spectre变种1，因为它是最普遍的。此外，根据英特尔公司的说法，与Meltdown和Spectre变种2相比，变种1不会在即将到来的新一代CPU硬件中被修复。

在知道实际条件之前，CPU会预测条件最可能的结果，然后继续进行相应的代码路径。在评估时不知道条件的结果有几种原因，例如，部分条件的缓存遗漏，尚未满足的复杂依赖关系，或者所需执行单元的瓶颈。通过隐藏这些延迟，如果条件预测正确的话，推测性执行会导致更快的整体执行速度（提升性能）。如果条件预测错误，执行的中间结果根本不会被提交到架构状态，最终效果好像处理器从未执行任何推测性执行。然而，<font color="green">在推测性执行过程中发生的任何微结构状态的修改，如缓存状态，都不会被还原。</font>

由于我们的NetSpectre攻击是通过网络安装的，所以受害者设备需要一个攻击者可以到达的网络接口。攻击者必须能够向受害者发送大量的网络数据包。但是，这些数据包不一定要在很短的时间内。此外，在我们的攻击中，数据包的内容不需要由攻击者控制。

与本地Spectre攻击相比，我们的NetSpectre攻击并不是分为两个阶段。相反，攻击者不断地通过操作来误导处理器，使其不断地运行到可利用的错误推测性执行中。NetSpectre不会跨越进程边界进行错误训练，而是通过将有效值和无效值交替传递到暴露的接口进行就地训练，例如有效和无效的网络数据包。对于我们的NetSpectre攻击，攻击者需要两个Spectre小工具，这两个小工具每收到一个网络数据包就会被执行：一个泄密小工具和一个传输小工具。泄密小工具以攻击者控制的索引访问位流，并根据所访问位的状态更改某些微体系结构状态。传输小工具执行一个任意操作，其执行时间取决于泄密小工具修改的微结构状态，隐藏在大量的噪声中，攻击者可以观察到网络数据包响应时间中的这种时间差。Spectre小工具在现代网络驱动程序、网络堆栈和网络服务实现中很常见。

为了说明我们的NetSpectre攻击的工作原理，我们在一个经过调整的场景中考虑一个类似于原始Spectre变种1的基本例子：<font color="red">list1</font>中的代码是一个函数的一部分，当收到一个网络数据包时，这个函数就会被执行。我们假设x是由攻击者控制的，例如，数据包头中的一个字段或某个API的索引。这段代码构成了我们的泄密小工具。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200909111259.png" style="zoom:50%;" />

代码片段以对x的约束检查开始，这是开发安全软件时的最佳做法。特别是，这个检查可以防止处理器读取 *bitstream* 之外的敏感内存。否则，一个越界的输入x可能会触发一个异常，或者可能导致处理器通过提供x=(要读取的秘密位的地址)-( *bitstream* 的基本地址)来访问敏感内存。

1. 攻击者发送多个网络数据包，使攻击者选择的x的值总是在边界内。这样可以训练分支预测器，增加分支预测器预测比较结果为真的机会。
2. 攻击者发送一个x超过 *bitstream* 的数据包，使得bitstream[x]是目标内存中的一个秘密位。
3. 根据最近的条件分支结果，分支预测器会假设边界检查为真，并推测性地执行内存访问。

虽然在条件的正确结果被计算出来后，架构状态的变化不会被提交，但微架构状态的变化不会被还原。在<font color="red">list1</font>中的代码中，这意味着虽然flag的值没有改变，但flag的缓存状态会改变。只有当bitstream[x]处的秘密位被设置，flag才会被缓存。

传输小工具就简单多了，因为它只需要在任意操作中使用flag。因此，小工具的执行时间将取决于flag的缓存状态。在最简单的情况下，传输小工具只是返回flag的值，而flag的值是由泄密小工具设置的。由于x越界的，flag的架构状态（即其值）不会发生变化，所以不会泄露秘密信息。但是，传输小工具的响应时间取决于flag的微观架构状态(即是否被缓存)，它确实会泄露一个秘密位。

为了完成攻击，攻击者要测量每一个秘密位泄露的响应时间。由于响应时间的差异在纳秒范围内，攻击者需要对大量的测量结果求平均值，以获得具有一定可信度的秘密值。事实上，我们的实验表明，当进行大量测量时，微结构状态的差异会变得明显。因此，攻击者可以先测量两种极端情况(即缓存和未缓存)，之后，为了提取真正的秘密位，进行尽可能多的测量，以足够的可信度来区分是哪种情况，例如，使用阈值或贝叶斯分类器。

我们将泄密小工具和传输小工具这两个小工具称为NetSpectre小工具。运行NetSpectre小工具可能需要发送一个以上的数据包。此外，可以通过不同的独立接口来访问泄密小工具和传输小工具，也就是说，攻击者必须可以访问这两个接口。<font color="red">图1</font> 说明了两种类型的小工具，本节后面将详细介绍。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200909161340.png" style="zoom:50%;" />

### 3.1 小工具位置

攻击目标的集合取决于NetSpectre小工具的位置。 如<font color="red">图2</font>所示，从总体上讲，有两个不同的小工具位置：小工具位于用户空间或内核空间中。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200909165458.png" style="zoom:50%;" />

#### 3.1.1 内核缺陷

网络驱动程序通常是在操作系统的内核中实现的，可以是一个固定的组件，也可以是一个内核模块。无论在哪种情况下，当收到网络数据包时，内核代码都会被执行。如果在处理网络数据包的过程中处理的任何内核代码都包含NetSpectre小工具，即攻击者控制的数据包的一部分被用作索引来引用位，那么NetSpectre攻击就有可能发生。

对内核代码的攻击是特别强大的，因为内核不仅有内核内存映射，通常还有整个物理内存。在Linux和macOS上，物理内存可以通过直接物理映射来访问，即每个物理内存位置都可以通过内核地址空间中预定义的虚拟地址来访问。Windows不使用直接物理映射，而是维护内存池，通常也会映射很大一部分物理内存。因此，利用内核中的NetSpectre小工具进行NetSpectre攻击，一般来说可以泄露存储在内存中的任意位。

#### 3.1.2 对用户空间的攻击

通常情况下，网络数据包不仅由内核处理，而且会传递给用户空间的应用程序，由其处理数据包的内容。因此，不仅是内核，用户空间应用程序也可能包含NetSpectre小工具。事实上，当网络数据包到达时，数据包经过路径上所有被执行的代码都可能是NetSpectre小工具，这包括服务器端和客户端的代码。

攻击用户空间应用的一个优势是攻击面大大增加，因为很多应用都在处理网络数据包，特别是在服务器上，有大量的服务在处理用户控制的网络数据包，例如，Web服务器、FTP服务器或SSH守护进程。同时，远程服务器也可以攻击客户机，例如，通过Web套接字，或SSH连接。与对内核空间的攻击相反，一般来说，对内核空间的攻击可以泄露系统内存中存储的任何数据，而对用户空间应用程序的攻击只能泄露被攻击应用程序的秘密数据。

这种特定应用的秘密数据包括应用本身的秘密数据，如凭证和密钥数据。因此，利用应用程序中的NetSpectre小工具进行的NetSpectre攻击可以访问应用程序处理的任意数据。此外，如果受害者是一个多用户的应用程序，例如，一个Web服务器，它也包含了多个用户的秘密数据。特别是对于流行的网站，这很容易影响到数千或数百万用户。

### 3.2 小工具类型

现在我们讨论不同的NetSpectre小工具，即将秘密数据位编码到微架构状态的泄密小工具和将微架构状态传输给远程攻击者的传输小工具。

#### 3.2.1 泄密小工具

第一种类型的小工具，即*泄密小工具*，通过改变一个微结构状态来泄漏秘密数据，这取决于一个内存位置的值，而这个位置是不能通过攻击者可以访问的任何接口直接访问的。需要注意的是，这种状态变化发生在受害者设备上，并不能通过网络直接观察到。

一个泄漏小工具可以泄漏一个bit位，甚至一个或多个字节。单比特小工具是最通用的，存储一个bit（二进制）的状态可以用许多微结构状态来完成，因为只需要区分两种情况（参见第4节）。Kocher等人用一个字节的小工具泄露了秘密数据，这简化了对秘密数据的访问，因为只需要使用字节索引，但使恢复过程复杂化，因为需要区分256种状态。对于本地Spectre攻击，恢复过程是由攻击者来实现的，因此复杂的恢复过程没有任何问题，仅仅是性能比较低，因为在隐蔽信道的接收侧必须进行很多次侧信道测试（如很多次Flush+Reload测试）。Lipp等人的研究表明，在类似的攻击中，用单bit隐蔽信道进行失序执行的传输速度比用字节式或多字节隐蔽信道的传输速度要快很多。NetSpectre攻击必须依靠小工具来实现恢复过程，大大减缓了传输速度。使用单bit小工具不仅有多个微架构元素可供选择，而且数据恢复起来也比较容易，同时，由于隐蔽信道传输需要进行的远程侧信道测试较少，数据传输速度也比较快。因此，我们在本文中重点研究单bit泄漏小工具。单bit泄漏小工具可以简单到如<font color="red">list1</font> 所示。在这个例子中，如果攻击者选择的位置的位被设置，则会缓存一个值（flag）。如果该位没有被设置，则该变量的缓存状态保持不变，也就是说，如果该变量之前没有被缓存，则不会被缓存。因此，攻击者可以利用这个小工具将秘密bits泄露到微结构状态中。

#### 3.2.2 传输小工具

与Spectre不同，NetSpectre需要一个额外的小工具来传输泄露的信息给攻击者。由于攻击者并不控制受害者设备上的任何代码，攻击者无法实现恢复过程，即把微架构状态转换回架构状态。此外，架构状态通常无法通过网络访问，因此，即使小工具将微架构状态转换为架构状态也无济于事。

从攻击者的角度来看，微结构状态必须在网络上变得可见。这不仅可以通过直接传输网络数据包的内容实现，还可以通过侧信道影响实现。事实上，微结构状态在某些情况下会变得对攻击者可见，例如，响应时间。我们将基于网络的向攻击者暴露微结构状态的代码片段称为*传输小工具*，它可以被攻击者触发，当然，*传输小工具*必须位于受害者设备上。有了*传输小工具*，微结构状态的监测就发生在远程机器上，但微结构的状态通过网络可访问的接口暴露出来。

在最初的Spectre攻击中，Flush+Reload被用来将微架构状态转移到架构状态，然后被攻击者读取，从而泄露秘密。最理想的情况是，如果受害者主机有这样一个Flush+Reload的小工具，并且可以通过网络观察到架构状态。然而，由于不太可能在受害者主机找到一个可利用的Flush+Relo小工具并访问架构状态，因此不能简单地将常规的Spectre小工具修改成NetSpectre攻击。

在最直接的情况下，通过网络数据包的延迟，微架构状态对于远程攻击者来说是可见的。<font color="red">list1</font> 中所示的泄漏小工具的一个简单的传输小工具只是访问变量flag。网络数据包的响应时间取决于变量的缓存状态，也就是说，如果变量被访问了，响应的时间就会减少。一般来说，如果这种差异是可以通过网络测量的，那么攻击者就可以观察到微结构状态的变化。



## 4. 远程微架构隐蔽信道

如上一节所述，NetSpectre攻击的关键是建立一个微架构的秘密通道，将信息暴露给远程攻击者。由于在我们的方案中，攻击者不能在目标系统上运行任何代码，我们假设传输任务是通过一个*传输小工具*发生的，其执行可以被攻击者触发。在本节中，我们演示了第一种基于远程访问的缓存攻击：*Thrash+Reload*（Evict+Reload的一个变种）。我们表明，通过这种远程缓存攻击，攻击者可以建立一个从目标设备上的推测性执行到攻击者机器上的远程接收端的秘密通道。此外，我们还提出了一种以前未知的基于AVX2指令的微架构隐蔽通道，这种隐蔽通道可以用于NetSpectre攻击，传输速率比远程缓存隐蔽通道更高。

### 4.1 远程缓存隐蔽信道

Kocher等人利用缓存作为微架构元素对泄露的数据进行编码。这就可以利用常见的缓存侧通道攻击（如Flush+Reload或Prime+Probe）来推断微架构状态，从而推断出编码的数据。

然而，并不是只有缓存才会保留这些可以在架构层面变得可见的微观架构状态。从DRAM、BTB或RSB等元素中提取微架构状态的方法是已知的。一般来说，每个微架构隐蔽信道的接收器都可以用来将微架构状态转移到架构状态。

利用缓存来发起Spectre攻击有三大优势：存在有效的方法使缓存状态可见，许多操作会修改缓存状态，因此在缓存中可见，并且，缓存命中和缓存未命中之间的时间差距比较大。Flush+Reload通常被认为是最细粒度、最精确的缓存攻击，噪声几乎为零。如果Flush+Reload不适用于某个场景，Prime+Probe被认为是另一个最佳选择。因此，目前公布的所有Spectre攻击都使用Flush+Reload或Prime+Probe的。

为了建立我们的第一个NetSpectre攻击，我们需要调整针对本地缓存的隐蔽信道技术。我们不直接测量内存访问时间，而是测量使用相应内存位置的网络请求的响应时间。因此，响应时间将受到用于攻击的变量的缓存状态的影响。由于内存访问速度比较快，因此缓存状态导致的响应时间差异将在纳秒范围内。

网络延迟受很多因素的影响，导致结果有噪声，但是，通过对大量网络数据包求平均值，可以降低噪声的影响。因此，攻击者需要对大量的测量结果求平均值，以获得可信度能被接受的秘密值。

<font color="red">图3</font> 显示，当进行大量测量时，微架构状态的差异确实可见。两种分布的平均值用虚的垂直线来表示。攻击者可以在测量值上使用分类器，或者先测量两种极端情况（缓存和未缓存），以获得真实测量值的阈值。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200910174158.png" style="zoom:50%;" />

但是，由于测量会破坏缓存状态，即变量总是在第一次测量后被缓存，因此攻击者需要一种方法来驱逐（或刷新）缓存中的变量。由于受害者不可能直接提供一个接口来刷新或驱逐变量，攻击者不能使用众所周知的针对高速缓存攻击方法，而只能采用更粗糙的方法。我们不采用Evict+Reload中的定向驱逐，而是简单地驱逐整个末级缓存，类似于Maurice等人的做法。因此，我们称这种技术为Thrash+Reload。为了在不执行代码的情况下对整个末级缓存进行驱逐，我们又必须使用一个通过网络访问的接口。最简单的形式是，从受害者向攻击者发送的任何数据包，例如文件下载，都有机会从缓存中驱逐变量。

<font color="red">图4</font> 显示了通过向受害者程序请求文件，从最后一级缓存中驱逐特定变量（即flag变量）的概率。受害者程序运行在Intel i5-6200U上，末级缓存为3MB。下载一个590KB的文件就足以驱逐变量，概率≥99%。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200910201722.png" style="zoom:50%;" />

有了区分缓存命中和未命中的机制，以及从缓存中泄露东西的机制，我们就拥有了缓存侧通道攻击或缓存隐蔽通道所需的所有构件。Thrash+Reload在网络接口上结合了这两种机制，形成了第一个远程缓存隐蔽通道。在我们的局域网实验中，我们实现了高达4比特/分钟的传输速率，错误率<0.1%，这比本地原生环境下的缓存隐蔽信道要慢得多，例如，最类似的攻击（Evict+Reload）的性能达到了13.6 kb/s，错误率为3.79%。

在本文中，我们使用远程缓存隐蔽信道进行远程Spectre攻击。远程缓存隐蔽信道，尤其是远程缓存侧信道攻击是一个有趣的研究方向，之前提出的许多攻击如果能够通过网络接口发起，这将是毁灭性的。

### 4.2 基于AVX的远程隐蔽信道

为了证明第一个不依赖缓存作为微架构元素的Spectre变体，我们需要一个隐蔽信道，该信道允许将信息从推测性执行传输到架构状态。因此，我们建立了一个基于AVX2指令时序差异的新型隐蔽信道。这种隐蔽信道具有低错误率和高性能的特点，与远程缓存隐蔽信道相比，它可以使我们的NetSpectre攻击性能得到显著提升。

为了省电，CPU可以关闭AVX2单元的上半部分电源，该单元用于对256位寄存器进行操作，一旦执行一条使用256位值的指令，该单元的上半部分就会被上电，如果该单元被使用不超过1ms，则会再次断电。

当上半部分电源关闭时，执行256位操作会产生显著的性能下降。例如，我们测量了在英特尔i5-6200U上对两个256位寄存器（VPAND）进行简单的位与位之间的AND操作的执行情况（包括测量开销）（参见<font color="red">图5</font>）。如果上半部分处于激活状态，则该操作平均需要210个周期，而如果上半部分处于关闭状态（即处于非激活状态），则该操作平均需要576个周期，结果相差366个周期。这个差值甚至比缓存命中和未命中的差值还要大，在同一系统中，缓存命中和未命中的差值只有160个周期。因此，AVX2指令的时序差比缓存命中和未命中的时序差更有利于远程微架构攻击。与缓存类似，读取AVX2指令的延迟也会破坏编码信息。因此，攻击者需要一种重置AVX2单元的方法，即关闭上半部分的电源。与缓存相比，这要简单得多，因为AVX2单元的上半部分在闲置1ms后会自动断电。因此，攻击者在下一次测量前只需等待至少1ms。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200910210833.png" style="zoom:50%;" />

<font color="red">图6</font> 显示了一条256位的AVX2指令(特别是VPAND)在AVX2单元不活动后的执行时间。如果不活动时间短于0.5ms，即最后一条AVX2指令的执行时间不超过0.5ms，那么在执行使用AVX2单元上半部分的AVX2指令时，不会有性能损失。在这之后，AVX2单元开始断电，会增加任何后续AVX2指令的执行时间，因为该单元必须再次上电，并且在此期间只模拟AVX2。AVX2单元在大约1ms后完全断电，如果在这种状态下执行任何AVX2指令，会导致最高的性能损。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200910210944.png" style="zoom:50%;" />

利用AVX2的泄漏小工具与利用缓存的泄漏小工具类似。<font color="red">list2</font> 显示了一个AVX2泄漏小工具的示例（伪）代码。\_mm256_instruction表示一个任意的256位AVX2指令，例如：_mm256_and_si256。如果*bitstream*中被引用位x被设置，则指令被执行，因此，AVX2单元的上半部分被通电。如果分支预测结果不正确，并且AVX2指令在推测性执行期间被访问，也是如此。注意，AVX2指令与*bitstream*或索引之间没有数据依赖，只有AVX2指令是否被执行的信息才会被用来通过隐蔽信道传输秘密bit信息。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200910211114.png" style="zoom:50%;" />

传输小工具和缓存的传输小工具类似。任何使用AVX2指令的函数，以及因此在网络上可以观察到的可测量的运行时间差异，都可以被用作传输小工具。即使是 <font color="red">list2</font> 中所展示的泄漏小工具也可以作为传输小工具。通过为x提供一个有效范围内的值，函数的运行时间取决于AVX2单元上半部分的状态。如果单元的上半部分之前被使用过（即'1'-bit被泄露），那么函数的执行速度比上半部分之前没有被使用（即'0'-bit被泄露）的速度要快。

有了这些组件，我们可以建立一个基于AVX的秘密信道。我们的隐蔽信道是第一个纯AVX隐蔽信道和第一个基于AVX的远程隐蔽信道。在本地实验环境中，我们实现了125 B/s的传输速率，错误率为0.58 %，在局域网中，我们实现了8 B/min的传输速率，错误率<0.1 %。我们可以看到，这个利用AVX2远程隐蔽信道的真实传输速率高于远程缓存隐蔽信道的真实传输速率，它能够让NetSpectre攻击达到更高的数据泄露速率。



## 5. 攻击变种

在本节中，我们将介绍两种NetSpectre攻击的变种。第一种攻击允许从目标系统的内存中逐位提取秘密数据，第二种攻击允许在远程机器上打破ASLR机制，为远程利用ASLR提供方便。我们使用基于Spectre变种1的小工具来说明，当然，也可以用任何位于处理远程数据包的代码路径中的Spectre小工具来实现。

### 5.1 从目标系统中提取数据

使用典型的 *NetSpectre 小工具*（参见第 3 节），提取过程包括 4 个步骤。请注意，虽然小工具不同，但*泄漏小工具*和*传输小工具*可能是相同的。步骤如下：

1. 误导分支预测器，
2. 重置微架构元素的状态，
3. 向微架构元素泄露一个bit位，
4. 将微架构元素的状态暴露在网络上。

在步骤1中，攻击者误导了受害者的分支预测器，以运行Spectre攻击。为了误导分支预测器，攻击者借助泄漏小工具的有效索引，确保分支预测器学会总是执行分支（即分支预测器推测条件为真）。请注意，这一步只依赖于泄漏小工具，没有反馈给攻击者。因此，微结构状态不必被重置或传输。

在步骤2中，攻击者必须重新设置微架构状态，以实现使用微架构元素对泄露的比特进行编码。这一步高度依赖于所使用的微架构元素，例如，当利用缓存时，攻击者从受害者那里下载一个大的文件（参见<font color="red">图4</font>），如果使用AVX2，攻击者只需等待1毫秒以上。在这一步之后，所有的要求都满足了，就可以从受害者那里泄露一个bit位。

在步骤3中，攻击者利用Spectre漏洞从受害者那里泄露一个bit位。由于在步骤1中，分支预测器被误导，向泄漏小工具提供越界的索引将执行微架构下的微操作，并修改微结构元素，即在微结构元素中对bit位进行编码。

第四步，攻击者要通过网络传输编码信息。这一步相当于原始Spectre攻击的第二阶段。与原始的Spectre攻击利用缓存攻击不同，攻击者在这一步中使用了第4节所述的传输小工具。攻击者发送一个网络数据包，由传输小工具处理，并测量从发送数据包到响应到达的时间。如第4节所述，这个往返时间取决于微结构元素的状态，从而取决于泄漏的bit位。

由于网络时延的变化，这四个步骤必须重复多次，以消除有由于网络波动造成的噪声。通常情况下，延迟的变化遵循一定的分布，这取决于多种因素，如距离、跳数、网络拥堵等。重复次数主要取决于网络连接的延迟方差。因此，根据延时分布，可以用统计方法推导出重复次数。在第6.1节中，我们对这种攻击变体进行评估，并为我们的攻击设置提供根据经验确定的次数。

### 5.2 远程打破目标系统上的ASLR

如果攻击者没有机会接触到泄露bit位的NetSpectre小工具，可以危害性较小的NetSpectre小工具，它不泄露实际数据，只泄露相应地址的信息。这样的小工具对于已经有本地代码执行的Spectre攻击并没什么危害，因为ASLR并不能防止本地攻击。然而，在远程场景下，破解ASLR是非常有价值的，如果在用户空间程序中发现了这样的NetSpectre小工具，就能破坏这个进程的ASLR。

<font color="red">list3</font> 显示了一个简单的泄漏小工具，它已经足以破解ASLR。在这个小工具的帮助下，破解ASLR包括3个步骤：

1. 误导分支预测器，

2. 访问越界索引来缓存一个（已知的）内存位置，

3. 通过网络测量函数的执行时间，以推断越界访问是否缓存了一部分。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200924224540.png" style="zoom:50%;" />

误导训练步骤与任何Spectre攻击中的相同，会导致相对于数组的推测性越界访问。如果攻击者在误导训练之后为x提供了一个越界值，那么这个索引处的数组元素就会被推测性地访问。假设使用一个字节数组和一个(无符号)64位的索引，攻击者可以(推测地)访问任何内存位置，因为如果基地址加上索引大于虚拟内存，索引会继续从起始地址寻找。如果这个内存位置的字节是有效的、可缓存的，那么在执行这个小工具后就会被缓存，因为推测性执行会把相应的内存位置取到缓存中。因此，这个小工具允许缓存当前虚拟内存中有效的任意内存位置，即当前应用程序的每个被映射的内存位置。

攻击者使用这个小工具来缓存一个已知位置的内存位置，例如，vsyscall页面，它被映射到每个应用程序的相同虚拟地址。然后，攻击者测量能够访问已被缓存内存位置的函数执行的时间，例如，旧版本的time或gettimeofday函数。如果函数执行得更快，越界数组索引实际上是缓存了这个函数所使用的内存位置，因此，从已知地址和数组索引的值，即与已知地址的相对偏移量，攻击者可以计算出泄漏小工具的实际地址。

在Linux上，ASLR的熵为30 b时，攻击者需要检查2<sup>30</sup>种可能的偏移。由于KPTI（以前的KAISER）补丁，在用户空间中，没有其他接近vsyscall页面的页面被映射。因此，在2<sup>30</sup>个可能的偏移中，只有一个有效的，因此是可缓存的偏移。我们可以通过二分搜索来寻找正确的偏移量，即推测性地尝试将一半的可能偏移量加载到缓存中，并进行一次检查。如果这一次是有效的，就说明可缓存的偏移量已被缓存，攻击者选择了正确的一半，否则，攻击者就继续加载另一半的偏移量。这就把打破ASLR需要的检查次数减少到只有30次。

虽然vsyscall是一个遗留功能，但我们发现它在Ubuntu 17.10和Debian 9.4（Google Cloud上实例的默认操作系统）上仍然被启用。此外，如果地址已知，可以使用任何其他函数或数据来代替vsyscall。如果知道泄漏小工具的地址，也可以用来去随机化其他任何可以通过网络测量其执行时间的函数。如果攻击者知道内核中一个固定偏移的内存页，该攻击也可以在内核中的NetSpectre小工具上运行，以破坏KASLR。



## 6. 评估

在本节中，我们评估NetSpectre和我们的概念验证实现的性能。第6.1节提供了一个定性的评估，第6.2节提供了NetSpectre攻击的定量评估。在评估中，我们使用了笔记本电脑（英特尔酷睿i5-4200M、i5-6200U、i7-8550U），以及台式电脑（英特尔酷睿i7-6700K、i7-8700K），谷歌云平台中未指定具体型号的基于Skylake的英特尔Xeon CPU，以及ARM Cortex A75。

### 6.1 泄露

为了在不同的设备上评估NetSpectre，我们构建了一个受害者程序，该程序在所有测试平台上都包含相同的泄漏小工具和传输小工具（参见第3节）。我们从受害者中泄露了已知值，以验证我们的攻击是否成功，并确定需要进行多少次测量。除了云端设置，所有的评估都是在本地实验室环境中完成的。我们在所有评估中使用了Spectre变种1，然而，其他Spectre变种也可以以同样的方式使用。

#### 6.1.1 台式机和笔记本电脑

与本地Spectre攻击（单次测量就已经足够）相比，NetSpectre攻击则需要大量的测量来区分具有一定可信度的bits数据。即使是在本地网络上，也需要大约10万次测量，才能将噪声降低到可以清楚看到比特之间差异的水平。通过重复攻击，噪声被降低，使其更容易区分bits数据。

对于我们的本地攻击，我们在受害者和攻击者之间使用千兆网络连接，这在本地网络中是一个典型的场景，但也适用于专用服务器和虚拟服务器的网络连接。我们测得网络延迟的标准差为15.6 µs。应用3σ准则，在至少88.8%的情况下，延迟与平均值偏差为±46.8 µs。这比攻击者想要测量的实际时序差大了近3个数量级，这也解释了为什么需要进行大量的测量。

我们的概念验证NetSpectre实现通过指定一个内存位流的越界索引，从受害者那里泄露任意bits数据。<font color="red">图7</font>显示了使用我们的概念验证实现一个字节的数据泄漏。对于每个比特，我们重复测量了1 000 000次。虽然我们只在直方图的最大值上使用了一个贝叶斯阈值，但我们可以清楚地区分 "0 "比特和 "1 "比特。更复杂的方法，例如机器学习方法，可能会进一步减少测量次数。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200929163255.png" style="zoom:50%;" />

#### 6.1.2 ARM设备

另外，在我们对ARM设备的评估中，我们使用了有线网络，因为在今天的无线连接中，网络延迟差异太大。我们测试的ARM内核在网络延迟方面的差异明显较大。我们测得网络延迟的标准差为128.5 µs。同样，利用3σ准则，我们估计至少有88.8%的测量值在±385.5 µs以内。

<font color="red">图8</font>显示了从ARM Cortex A75受害者泄露的两个bit位--'0'和'1'。即使延迟的差异较大，简单的阈值化方法也可以分离直方图的最大值。因此，该攻击也适用于ARM设备。

<img src="https://gitee.com/sctb/abin_pictures/raw/master/imgs/20200929163335.png" style="zoom:50%;" />

#### 6.1.3 云计算实例

对于云实例，我们在谷歌云平台上测试了我们的概念验证实现。我们在同一区域创建了两个虚拟机实例，一个作为攻击者，一个作为受害者。对于这两个实例，我们使用默认的Ubuntu 16.04.4 LTS作为操作系统。
测量到的网络延迟的标准差为52.3 µs。因此，我们估计至少有88.8%的测量值在±156.9 µs的范围内。我们通过在两个实例之间运行NetSpectre攻击来验证我们可以成功泄露数据。
为了适应网络延迟较高的波动，我们将测量次数增加了20倍，即每个比特都被测量了20 000 000次。<font color="red">图9</font>显示了谷歌云实例上 "0 "bit和 "1 "bit的（平滑）直方图。虽然仍然可以看到噪声，但足以区分bits，从而从受害者云实例中泄露任意bits数据。

### 6.2 NetSpectre 性能

为了评估NetSpectre的性能，我们从目标设备中泄露了已知值。这使我们不仅可以确定攻击者泄漏内存的速度，还可以确定位错误率，即预期的位错误数量。

#### 6.2.1 本地网络

在本地网络上的攻击能达到最好的性能，因为网络延迟的差异明显小于互联网上的差异（参见第6.1.3节）。在我们的实验室设置中，我们每比特重复测量1 000 000次，以便能够可靠地从受害者那里泄漏字节。平均来说，泄漏一个字节需要30分钟，相当于每个比特约4分钟。使用AVX隐蔽通道而不是缓存，可以将泄漏整个字节所需的时间减少到只有8分钟。

为了打破ASLR，我们需要缓存隐蔽通道。平均来说，这可以在2 h内远程打破随机化。
我们在实验中使用了 stress -i 1 -d 1，以模拟一个真实的环境。虽然我们本以为我们的攻击在完全空闲的服务器上效果最好，但我们并没有看到适度的服务器负载带来的任何负面影响。事实上，它们甚至略微提高了攻击性能，其中一个原因是，较高的服务器负载会产生较多的内存和缓存访问，从而促进了缓存的变化（参见第4节），而这正是我们攻击的性能瓶颈。另一个原因是，较高的服务器负载可能会耗尽计算泄漏小工具中的边界检查所需的执行端口，从而增加了CPU执行条件的机会。

我们在本地网络中的NetSpectre攻击相对较慢。 但是，特别是专门的恶意软件攻击，例如APT，通常会在局域网中活跃数月之久。 在这样的时间范围内，攻击者确实可以从同一网络上的目标系统泄漏所有感兴趣的数据。

#### 6.2.2 云网络

我们使用Google Cloud上的两个虚拟机实例评估了在云环境中的性能。 这些虚拟机具有快速的网络连接，我们将这两个实例配置为每个使用2个虚拟CPU，通过4Gbit / s的网络连接。 在此设置中，我们对每bit位重复测量2000万次，以获得无错误的字节泄漏。 平均而言，缓存隐蔽信道泄漏一个字节需要8个小时，而使用AVX隐蔽信道需要3个小时。
尽管这比较慢，但它表明在公共云中独立实例之间进行远程Spectre攻击是可行的。 特别是，APT通常会运行数周或数月， 如此长的时间范围显然足以在云环境中使用NetSpectre攻击来泄漏敏感数据，例如加密密钥或密码。



## 7. 修复Sectre攻击的挑战

在本节中，我们将讨论针对Spectre最先进的修复措施存在的局限性，以及它们为什么不能完全防止NetSpectre攻击。此外，我们还讨论了如何在网络层预防NetSpectre攻击。最后，我们概述了未来对Spectre攻击的研究以及Spectre修复措施的挑战。

### 7.1 最新的Spectre攻击对策

由于起源不同，Spectre变种1和变种2使用不同的对策来修复。英特尔发布了微代码更新，以防止Spectre变种2攻击中典型间接分支的跨进程和跨权限误导。没有防止直接分支误导的微代码更新，因为这很容易在运行过程中进行，即在相同的权限级别和相同的进程上下文中进行。对于Spectre变种1攻击，已经提出了一系列纯软件的应对措施。

英特尔和AMD建议使用lfence指令作为推测执行的隔离。这条指令必须在安全临界检查后插入，以停止投机性执行，但是，在每次边界检查中加入这条指令会有很大的性能开销。

此外，我们的实验表明，lfences确实可以阻止推测性执行，但不能阻止推测性代码获取和其他执行前发生的微架构行为，如AVX功能单元的上电、指令缓存填充和TLB填充。根据我们的实验，lfences确实可以对抗传统的Spectre小工具，但并不能对抗我们在本文中使用的所有Spectre小工具，参见<font color="red">list2</font>和<font color="red">list3</font>，它们可以通过执行前发生的微架构行为泄漏信息。然而，我们相信有一些方法可以使用lfences的方式来修复数据泄漏。

Microsoft在其编译器中实现了对易受攻击的代码路径（即Spectre小工具）的自动检测，以将推测障碍限制在这些小工具中。然而，Kocher表明，自动分析会遗漏很多小工具。由于微软只对已知的小工具使用黑名单，编译器不会自动保护许多小工具，特别是非典型的小工具（如破解ASLR的小工具）。

在Linux内核中，可被利用的小工具是借助静态代码分析器手动识别的。与基于编译器的方法也类似，这需要完全了解哪些代码片段是可利用的。

最后，直到现在，人们还普遍忽视了间接分支误导（Spectre变种2）也是可能的攻击。然而，由于误导训练，攻击的可能性更大。

### 7.2 网络层的修复

由于NetSpectre是一种基于网络的攻击，所以不能只通过缓解Spectre来防御，还要通过网络层的对策来防御。一个微不足道的NetSpectre攻击很容易被DDoS保护检测到，因为从同一个源头发送了多个同样的数据包。然而，攻击者可以在每秒的数据包和每秒泄漏的bits数据之间选择任何权衡。因此，可以简单地将泄漏比特的速度降低到DDoS监控能够检测到的阈值以下。这对于任何试图检测正在进行的攻击的监测都是如此，例如，入侵检测系统。虽然理论上无法阻止攻击，但在某些时候，攻击变得不可行，因为泄漏一个比特所需的时间严重增加。

缓解NetSpectre的另一种方法是在网络延迟中加入人工噪声。由于测量的次数取决于网络延迟的方差，额外的噪声需要攻击者进行更多的测量。因此，如果网络延迟的方差足够高，NetSpectre攻击就会因为需要大量的测量而变得不可行。

这两种方法在实践中都可以减轻NetSpectre攻击。然而，由于攻击者可以适应和改进攻击，因此，假设现在选择的噪声水平和监测阈值在不久的将来仍然有效是不安全的。

### 7.3 未来研究的挑战

如前几节所讨论，Spectre攻击被完全修复还有很长的路要走。目前提出的缓解措施只是解决了表象，而没有直接解决根本原因，即性能和安全之间不恰当的权衡，导致了我们目前的推测性执行。我们确定了未来在Spectre攻击和修复措施方面的5个挑战（C1到C5）。

- C1：小工具比预期的更通用。

  特别是我们用来破解ASLR的小工具到目前为止还未被认为是危险的。另外，我们使用的基于AVX的小工具到目前为止也没有被认为是危险的。小工具也可能由许多小代码组成，这些小代码会传递秘密值，直到在以后的时候，秘密值被泄露给攻击者。由于Spectre向攻击者泄露信息的组件是一个隐蔽信道，似乎识别所有小工具的基本问题可以简化为识别所有秘密信道的问题。目前，我们还没有识别系统中所有隐蔽信道的技术。

- C2: 自动保护所有的小工具并非易事。

  对于Spectre变种1，我们提出的解决方案是使用推测障碍。由于我们不能指望每个开发人员都能识别出易受攻击的小工具并正确地修复它们，因此最先进的解决方案会尝试自动检测易受攻击的小工具并在编译时修复它们。目前还不清楚静态代码分析是否足以检测所有易受攻击的小工具，尤其是当它们分散在各个函数中时。在这种复杂的情况下，动态分析可能会带来更好的结果。然而，动态分析自然存在不完全性，因为在动态分析中可能无法达到程序的某些部分。此外，编译器产生的Spectre小工具有可能在源代码中不可见，例如，双倍取数错误就可能发生。这就很难在前期被发现，完全破坏了采取的安全措施。

- C3：黑名单本质上是不完整的。

  目前的方法依靠黑名单来自动修补可利用的小工具。然而，这意味着我们确切地了解哪些代码片段是可利用的，哪些不是。正如本文所显示的，小工具可能看起来与预期的不同，这表明了黑名单方法的不完整性。从反面考虑可能是一个更好的方向，即使用（可证明的）不可利用的小工具的白名单而不是黑名单。不过，这需要大量的研究来证明代码碎片的不可开发性。

- C4：跨进程和跨权限级别的误导比原地误导更容易解决。

  目前的对策主要是为了防止跨进程边界，特别是跨权限级别的Spectre攻击。然而，正如本文所示，如果误导训练发生在同一进程内部，这种对策是无效的。这种方法不仅适用于Spectre变种1，也适用于Spectre变种2。Retpoline是目前唯一能防止这些Spectre变种2攻击的修复措施，它能有效地阻止处理器的任何进一步推测。然而，Retpoline并不是一个完美的解决方案，因为它会产生巨大的性能开销，并增加另一个侧信道。

  如果攻击者只能在同一进程内污染具有有效分支目标的分支，即应用了所有的微代码更新，Retpoline可以被我们提出的一个更简单的构造所取代。我们提议在每个可能的调用目标处插入推测障碍。这比用Retpolines的结构更清晰。因此，每个错误的间接调用都会在实际执行代码之前立即中止。对于直接调用，编译器可以跳过猜测障碍，以减少性能影响。不过，这个解决方案和Retpoline一样，对整体性能的影响还是很大的。目前还不清楚是否可以在不产生高性能开销和不引入新问题的情况下，完全防止同一进程内的Spectre攻击。

- C5：安全机制可能产生不必要的影响。

  Retpoline 补丁通过在堆栈上篡改返回值，基本上向 CPU 隐藏了间接调用的目标。然而，这导致了其他安全机制的副作用，因为Retpoline的行为类似于改变控制流的漏洞。特别是控制流完整性等安全机制必须进行调整，以避免将Retpolines误检测为攻击。不过，问题还是出现了，Spectre修复措施如何与其他CFI实现（尤其是在硬件中）以及其他安全机制进行交互，以及我们在结合安全机制时是否必须接受权衡。总的来说，我们需要研究哪些安全机制可能会产生不利的影响，而超过安全方面的收益。



## 8. 总结

在本文中，我们提出了NetSpectre，第一个远程Spectre变种1攻击。我们展示了第一个通过网络进行的基于访问的远程Evict+Reload缓存攻击，其性能为每小时15比特。我们还演示了第一个不使用缓存隐蔽信道的Spectre攻击。特别是在远程Spectre攻击中，我们的基于AVX的新型高性能隐蔽信道的性能明显优于远程缓存隐蔽信道。我们的NetSpectre攻击与基于AVX的隐蔽信道相结合，每小时从目标系统中泄露60比特。我们在本地网络以及谷歌云中验证了NetSpectre。

NetSpectre标志着Spectre攻击模式的转变，即从本地攻击到远程攻击。通过我们的NetSpectre攻击，更多的设备将暴露在Spectre攻击之下，范围更广，数量更多。现在，Spectre攻击还必须考虑到那些根本不运行任何潜在攻击者控制的代码的设备。我们证明，在远程攻击中，NetSpectre可以用来打破远程系统上的地址空间布局随机化（ASLR）。正如我们在本文中所讨论的那样，未来对Spectre攻击和Spectre修复措施的研究还存在一系列挑战。