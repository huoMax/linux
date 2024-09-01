# Arm64页表初始化机制

本文所分析Linux内核基于v5.10版本。

在Linux 5.10 内核中，ARM64架构的页表初始化涉及多个阶段，并依赖设备树来获取内存布局等信息。以下是页表初始化的几个关键阶段及其如何从设备树中读取内存并初始化的简要说明：

## 早期引导阶段

Bootloader: 在最早的引导阶段，通常是由bootloader来设置最初的页表，并且启动CPU到EL2（如果支持的话）或EL1特权级。内核开始执行时，它接管了从bootloader继承的简单页表设置（暂时不管这部分的过程）。

## 早期汇编入口

ARM64内核的实际入口点是`primary_entry`，这个符号位于arch/arm64/kernel/head.S文件中，在经过汇编阶段的初始化后，head.s最终跳转到C语言阶段，第一个函数是start_kernel：

1. `__create_page_tables`：这个函数创建一个简单的、早期的页表结构。这些页表用于将物理地址空间映射到虚拟地址空间，通常是一个线性映射，即物理地址与虚拟地址一一对应。这样可以简化初期的内存访问逻辑；
2. `__enable_mmu`：该函数会使用`__create_page_tables`创建的页表启用MMU，并将CPU切换到分页模式；

## 内核入口初始化

1. `start_kernel`: 该函数是Linux内核的主要入口点，不仅在ARM64架构中使用，在其他架构中也是通用的。架构相关的内容会在`setup_arch`中完成初始化；

## 架构相关初始化

主要由`setup_arch`这个函数负责架构相关初始化，它会解析设备树，设置页表，初始化内存管理，并完成其他与硬件相关的设置；

### 解析设备树

#### 解析基本节点

`setup_machine_fdt`: 在 setup_arch 中调用，负责从设备树的物理地址加载设备树，验证其有效性，然后继续进行后续的初始化:

```C
static void __init setup_machine_fdt(phys_addr_t dt_phys)
{
 int size;
 void *dt_virt = fixmap_remap_fdt(dt_phys, &size, PAGE_KERNEL);
 const char *name;

 if (dt_virt)
  memblock_reserve(dt_phys, size);

 if (!dt_virt || !early_init_dt_scan(dt_virt)) {
  pr_crit("\n"
   "Error: invalid device tree blob at physical address %pa (virtual address 0x%p)\n"
   "The dtb must be 8-byte aligned and must not exceed 2 MB in size\n"
   "\nPlease check your bootloader.",
   &dt_phys, dt_virt);

  while (true)
   cpu_relax();
 }

 /* Early fixups are done, map the FDT as read-only now */
 fixmap_remap_fdt(dt_phys, &size, PAGE_KERNEL_RO);

 name = of_flat_dt_get_machine_name();
 if (!name)
  return;

 pr_info("Machine model: %s\n", name);
 dump_stack_set_arch_desc("%s (DT)", name);
}
```

1. `fixmap_remap_fdt`：从物理地址映射到虚拟地址空间，并返回设备树的大小；
2. `memblock_reserve`：保留设备树在物理内存中的区域，防止它被内核的内存管理系统重新分配；
3. `early_init_dt_scan`：证和扫描设备树的内容。这个函数负责解析设备树的结构，并提取其中的关键信息；
   1. `early_init_dt_verify`：验证设备树的有效性
   2. `early_init_dt_scan_nodes`:解析设备树中的各个节点，从设备树中提取关键的系统配置和硬件信息；

```C
void __init early_init_dt_scan_nodes(void)
{
 int rc = 0;

 /* Retrieve various information from the /chosen node */
 rc = of_scan_flat_dt(early_init_dt_scan_chosen, boot_command_line);
 if (!rc)
  pr_warn("No chosen node found, continuing without\n");

 /* Initialize {size,address}-cells info */
 of_scan_flat_dt(early_init_dt_scan_root, NULL);

 /* Setup memory, calling early_init_dt_add_memory_arch */
 of_scan_flat_dt(early_init_dt_scan_memory, NULL);
}
```

Linux采用`of_scan_flat_df`来遍历设备树中的指定节点，并对指定节点调用相关的回调函数，`early_init_dt_scan_nodes`主要针对：**chosen节点**、**根节点**、**内存节点**三种进行扫描，并调用相应的回调函数，而内存节点的回调函数是`early_init_dt_scan_memory`：

```C
int __init early_init_dt_scan_memory(unsigned long node, const char *uname,
         int depth, void *data)
{
 ...
 /* We are scanning "memory" nodes only */
 if (type == NULL || strcmp(type, "memory") != 0)
  return 0;
  ...
 // 获取内存区域信息
 reg = of_get_flat_dt_prop(node, "linux,usable-memory", &l);
 if (reg == NULL)
    reg = of_get_flat_dt_prop(node, "reg", &l);
 if (reg == NULL)
     return 0;
 // 解析reg属性，获取endp，它指向reg属性的结束位置
 endp = reg + (l / sizeof(__be32));

 // 循环解析内存块
 while ((endp - reg) >= (dt_root_addr_cells + dt_root_size_cells)) {
    u64 base, size;

    // 逐内存块解析，内存块大小由dt_root_addr_cells和dt_root_size_cells大小决定
    base = dt_mem_next_cell(dt_root_addr_cells, &reg);
    size = dt_mem_next_cell(dt_root_size_cells, &reg);

    // 将解析出的内存块添加到memblock中
    early_init_dt_add_memory_arch(base, size);
 }
}
```

而*dt_root_addr_cells*和*dt_root_size_cells*是在设备树根节点中解析出来的，分别对应#address-cells和#size-cells，以rk3568设备树举例，它表示每次解析64比特大小内存块（2个__be32），组成64位地址（2个__be32）：

```C
/ {
 compatible = "forlinx,rk3568\0rockchip,rk3568-evb1-ddr4-v10\0rockchip,rk3568";
 interrupt-parent = <0x01>;
 #address-cells = <0x02>;
 #size-cells = <0x02>;
 model = "Forlinx RK3568-C Board";
}
```

#### 解析设备节点

可以看到，`early_init_dt_scan_nodes`只处理了**chosen节点**、**根节点**、**内存节点**，而对于设备节点，则是在`unflatten_device_tree`中处理，该函数被`setup_arch`调用，用于将扁平设备树转化为内核内部的设备节点树结构，解析设备节点，生成对应的设备节点结构体，并添加到global list中。

```C
void __init unflatten_device_tree(void)
{
 __unflatten_device_tree(initial_boot_params, NULL, &of_root,
    early_init_dt_alloc_memory_arch, false);

 /* Get pointer to "/chosen" and "/aliases" nodes for use everywhere */
 of_alias_scan(early_init_dt_alloc_memory_arch);

 unittest_unflatten_overlay_base();
}
```

```C
struct device_node {
 const char *name;                    // 设备节点名
 phandle phandle;                     // 设备树中引用节点的唯一标识符
 const char *full_name;               // 设备节点的完整路径名称，通常从设备树的根节点开始，包括所有父节点的名称
 struct fwnode_handle fwnode;

 struct property *properties;         // 设备节点属性链表，每个节点表示节点的一个属性
 struct property *deadprops;          // 存储已被删除的设备树属性的链表
 struct device_node *parent;          // 父节点指针
 struct device_node *child;           // 孩子节点指针
 struct device_node *sibling;         // 兄弟节点指针
#if defined(CONFIG_OF_KOBJ)
 struct kobject kobj;
#endif
 unsigned long _flags;                // 用于存储设备节点的标志信息
 void *data;
#if defined(CONFIG_SPARC)
 unsigned int unique_id;
 struct of_irq_controller *irq_trans;
#endif
};
```

```C
void *__unflatten_device_tree(const void *blob,
         struct device_node *dad,
         struct device_node **mynodes,
         void *(*dt_alloc)(u64 size, u64 align),
         bool detached)
{
 ...
 /* First pass, scan for size */
 size = unflatten_dt_nodes(blob, NULL, dad, NULL);
 if (size < 0)
  return NULL;

 size = ALIGN(size, 4);
 pr_debug("  size is %d, allocating...\n", size);

 /* Allocate memory for the expanded device tree */
 mem = dt_alloc(size + 4, __alignof__(struct device_node));
 if (!mem)
  return NULL;
  ...
 /* Second pass, do actual unflattening */
 unflatten_dt_nodes(blob, mem, dad, mynodes);
 if (be32_to_cpup(mem + size) != 0xdeadbeef)
  pr_warn("End of tree marker overwritten: %08x\n",
   be32_to_cpup(mem + size));
}
```

主要功能是将一个扁平化的设备树结构展开为内核可以使用的树状设备节点结构 (struct device_node)，*blob*指向扁平设备树的指针，*dad*指向父节点，这里为NULL，*mynodes*用于存储展开后的设备树根节点指针，这里被设置为全局变量`of_root`，`dt_alloc`是一个用于分配内存的回调函数，这是使用的是`early_init_dt_alloc_memory_arch`。

`__unflatten_device_tree`使用`unflatten_dt_nodes`扫描两次设备树，第一次扫描是为了计算设备树展开后所需的内存大小，但这次扫描并不会实际展开设备树。而是在第二次扫描中，将设备树展开到第一次扫描分配的内存区域中，并将设备树头节点存储在*mynodes*中。

`unflatten_dt_nodes`会遍历设备中的每一个节点，主要是利用以下循环方式，先使用`of_fdt_device_is_available`检测设备节点是否可用（status），之后调用`populate_node`主要行为是，在第一次扫描中创建的设备树内存中，为设备节点的struct device预留空间（不是真正分配内存，只是在已经分配好的内存区域中再次划分），并提取设备节点的各种信息，填充到struct device_node中。

而我们注意到，我们只为设备树中的设备节点分配一次内存空间，使用的回调函数是`early_init_dt_alloc_memory_arch`，它实际上是调用memblock子系统为我们分配内存空间的（内核早期）。

> memblock子系统的内存信息获取，主要分为两部分：
>
> 1. setup_arch->efi_init->reserve_regions：在 EFI 启动的系统中，EFI 固件会提供一份内存地图，描述了系统中的各个物理内存区域的用途，例如可用内存、保留内存、EFI 专用内存等。reserve_regions 会遍历这份内存地图，并根据内存类型做出相应的处理。
>
> 2. early_init_dt_scan_memory：在设备树解析memory节点时往memblock中注册内存信息，但是部分设备树中可能没有memory节点，例如rk3568，rk3568提供的设备树中并未提供memory节点，memory的信息是通过uboot启动并更新到设备树中。

```C
static void * __init early_init_dt_alloc_memory_arch(u64 size, u64 align)
{
 void *ptr = memblock_alloc(size, align);

 if (!ptr)
  panic("%s: Failed to allocate %llu bytes align=0x%llx\n",
        __func__, size, align);

 return ptr;
}
```

```C
 for (offset = 0;
      offset >= 0 && depth >= initial_depth;
      offset = fdt_next_node(blob, offset, &depth)) {
  if (WARN_ON_ONCE(depth >= FDT_MAX_DEPTH))
   continue;

  if (!IS_ENABLED(CONFIG_OF_KOBJ) &&
      !of_fdt_device_is_available(blob, offset))
   continue;

  if (!populate_node(blob, offset, &mem, nps[depth],
       &nps[depth+1], dryrun))
   return mem - base;

  if (!dryrun && nodepp && !*nodepp)
   *nodepp = nps[depth+1];
  if (!dryrun && !root)
   root = nps[depth+1];
 }
```

值得一提的是，并不是所有的设备节点都有`status`信息，而Linux的做法是，如果没有检测到`status`属性，则默认认为设备可用（等同于okay）：

```C
static bool of_fdt_device_is_available(const void *blob, unsigned long node)
{
 const char *status = fdt_getprop(blob, node, "status", NULL);
 // 如果没有找到status属性，则返回true，等同于status == okay
 if (!status)
  return true;

 if (!strcmp(status, "ok") || !strcmp(status, "okay"))
  return true;

 return false;
}
```

### memblock子系统初始化

ARM64 架构在 Linux 内核启动过程中使用 memblock 子系统进行管理系统的物理内存。

主要初始化过程是在*setup_arch->arm64_memblock_init*中，它的内存信息来源是设备树解析memory节点和EFI提供的内存布局信息，对于之前已经添加的内存信息，在`arm64_memblock_init`会做出一些规范性检查，如是否超出物理地址空间限制、是否超出线性映射范围，是否是关键内存区域、应用内存限制等。

同时`arm64_memblock_init`还会进一步初始化内存布局，例如随机化内存起始地址、处理高端内存区域、配置DMA等。

### 设定初始页表

在内核使用内存前，需要初始化内核的页表，初始化页表主要由`paging_init`函数实现：

```C
void __init paging_init(void)
{
 // 将内核的顶级页表映射到一个固定的虚拟地址空间中，用于之后修改页表
 pgd_t *pgdp = pgd_set_fixmap(__pa_symbol(swapper_pg_dir));

 // 将内核的代码段、数据段、BSS 段等关键区域映射到虚拟内存空间中
 map_kernel(pgdp);

 // 映射物理内存区域
 map_mem(pgdp);

 pgd_clear_fixmap();

 cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
 init_mm.pgd = swapper_pg_dir;

 memblock_free(__pa_symbol(init_pg_dir),
        __pa_symbol(init_pg_end) - __pa_symbol(init_pg_dir));

 memblock_allow_resize();
}
```

`paging_init`会先通过`pgd_set_fixmap`将内核的顶级页表 (swapper_pg_dir) 映射到一个固定的虚拟地址空间，以便之后可以修改页表，swapper_pg_dir是内核页表的根。这个函数会返回`pgdp`，Linux之后的映射会根据这个指针来修改页表。

`pagging_init`主要会做两次映射，第一次是`map_kernel`，将内核映像映射到内核空间的虚拟地址；第二次映射是`map_men`，做物理内存的线性映射。

我们主要分析物理内存的映射，注意，`map_men`做的是线性映射，也就是说它确保整个物理内存，包括内核本身，都被统一映射到内核的线性地址空间中：

```C
static void __init map_mem(pgd_t *pgdp)
{
 ...
 /* map all the memory banks */
 for_each_mem_range(i, &start, &end) {
  if (start >= end)
   break;
  __map_memblock(pgdp, start, end, PAGE_KERNEL_TAGGED, flags);
 }

 __map_memblock(pgdp, kernel_start, kernel_end,
         PAGE_KERNEL, NO_CONT_MAPPINGS);
 memblock_clear_nomap(kernel_start, kernel_end - kernel_start);
 ...
}
```

map_mem会通过一个for循环，依次线性映射所有物理内存地址（通过__map_memblock），而对于内核的代码段和数据段，则比较特殊，会先标记为**NOMAP**跳过映射，等其他物理内存地址映射完之后再进行映射；

在`for_each_mem_range`中，会遍历memblock中的每一个内存区域：

```C
#define for_each_mem_range(i, p_start, p_end) \
 __for_each_mem_range(i, &memblock.memory, NULL, NUMA_NO_NODE, \
        MEMBLOCK_NONE, p_start, p_end, NULL)
```

**memblock.memory** 是一个描述系统中物理内存区域的全局数据结构，`for_each_mem_range`会从中获取每个内存区域的起始地址（start）和结束地址（end），之后调用`__map_memblock`函数，将这些内存区域映射到虚拟空间中，它主要是调用了`__create_pgd_mapping`：

```C
static void __create_pgd_mapping(pgd_t *pgdir, phys_addr_t phys,
     unsigned long virt, phys_addr_t size,
     pgprot_t prot,
     phys_addr_t (*pgtable_alloc)(int),
     int flags)
{
 unsigned long addr, end, next;
 pgd_t *pgdp = pgd_offset_pgd(pgdir, virt);

 /*
  * If the virtual and physical address don't have the same offset
  * within a page, we cannot map the region as the caller expects.
  */
 if (WARN_ON((phys ^ virt) & ~PAGE_MASK))
  return;

 phys &= PAGE_MASK;
 addr = virt & PAGE_MASK;
 end = PAGE_ALIGN(virt + size);

 do {
  next = pgd_addr_end(addr, end);
  alloc_init_pud(pgdp, addr, next, phys, prot, pgtable_alloc,
          flags);
  phys += next - addr;
 } while (pgdp++, addr = next, addr != end);
}
```

该函数的作用就是为计算当前PGD所能覆盖的虚拟地址范围的结束位置，然后在当前PGD范围内进行映射，如果memblock超过了这个范围，则跳到下一个PGD中建立映射，而`alloc_init_pud`会逐级别向下递归进行映射（PMD、PTE）。

### 内存区域初始化

dma_contiguous_reserve();
reserve_crashkernel();

1. memblock_add: 内核在解析设备树后，会调用memblock_add函数将设备树中描述的物理内存区域注册到内核的内存管理系统中。这些物理内存区域稍后会用于动态页表的建立;

2. 动态页表初始化：
   1. map_mem: 解析完设备树并获取到内存区域后，内核会调用map_mem或类似函数来映射内存和设备地址空间。这个阶段是动态页表初始化的开始，内核根据实际硬件配置和内存布局动态创建页表。
   2. create_mapping: 该函数会根据设备树中定义的物理内存区域创建相应的虚拟内存映射。这涉及到一级、二级、三级甚至四级页表的创建，具体取决于所需的映射范围和内存区域的大小。

3. 最终内存管理器初始化：
   1. mem_init: 最终，内核调用mem_init函数完成内存管理器的初始化工作。这一步中会调用free_unused_memmap释放掉不再需要的内存区域，调整和优化内存映射，并且开启进一步的内存管理功能，如页框分配器；
      1. paging_init:用于初始化内核页表和内存分页机制的函数
   2. setup_vm_final: 这是一个重要的函数，确保所有的内存区域都已经被正确映射，并为用户空间的运行做好准备。

4. 启动内核态分页（Enable Kernel Mode Paging）：
   1. __enable_mmu: 在初始化完成后，内核最终会调用__enable_mmu函数来开启MMU（内存管理单元），从而启用分页功能，并使所有的虚拟地址映射生效。

---

## Linux设备树相关接口

|变量/结构|作用|所在文件|
|:-:|:-:|:-:|
|initial_boot_params|全局变量，指向扁平设备树的全局指针|include/linux/of_fdt.h|
|of_root|全局变量，指向内核设备树节点的首节点|drivers/of/base.c|
|struct device_node|设备节点结构体，描述设备节点信息|include/linux/of.h|

|函数名|作用|所在文件|
|:-:|:-:|:-:|
|*of_scan_flat_dt*|遍历设备树节点，调用指定回调函数|drivers/of/fdt.c|
|*fdt_next_node*|遍历设备树节点，从当前节点开始，找到下一个节点，并返回节点的偏移量，同时更新节点的深度|scripts/dtc/libfdt/fdt.c|
|*fdt_get_name*|获取当前节点的名称，名称在设备树中用于识别和定位节点|scripts/dtc/libfdt/fdt_ro.c|
|*early_init_dt_scan_memory*|回调函数，用于解析设备树中的memory节点|drivers/of/fdt.c|

`of_scan_flat_dt`：

```C
/**
 * of_scan_flat_dt - scan flattened tree blob and call callback on each.
 * @it: callback function
 * @data: context data pointer
 *
 * This function is used to scan the flattened device-tree, it is
 * used to extract the memory information at boot before we can
 * unflatten the tree
 */
int __init of_scan_flat_dt(int (*it)(unsigned long node,
         const char *uname, int depth,
         void *data),
      void *data)
{
 const void *blob = initial_boot_params;
 const char *pathp;
 int offset, rc = 0, depth = -1;

 if (!blob)
  return 0;

 for (offset = fdt_next_node(blob, -1, &depth);
      offset >= 0 && depth >= 0 && !rc;
      offset = fdt_next_node(blob, offset, &depth)) {

  pathp = fdt_get_name(blob, offset, NULL);
  rc = it(offset, pathp, depth, data);
 }
 return rc;
}
```
