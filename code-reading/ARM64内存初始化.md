# ARM64 内存初始化

最开始的ARM64启动代码位于*arch/arm64/kernel/head.S*中：

```asm
SYM_CODE_START(primary_entry)
 bl record_mmu_state
 bl preserve_boot_args
 bl create_idmap

 /*
  * If we entered with the MMU and caches on, clean the ID mapped part
  * of the primary boot code to the PoC so we can safely execute it with
  * the MMU off.
  */
 cbz x19, 0f
 adrp x0, __idmap_text_start
 adr_l x1, __idmap_text_end
 adr_l x2, dcache_clean_poc
 blr x2
0: mov x0, x19
 bl init_kernel_el   // w0=cpu_boot_mode
 mov x20, x0

 /*
  * The following calls CPU setup code, see arch/arm64/mm/proc.S for
  * details.
  * On return, the CPU will be ready for the MMU to be turned on and
  * the TCR will have been set.
  */
#if VA_BITS > 48
 mrs_s x0, SYS_ID_AA64MMFR2_EL1
 tst x0, ID_AA64MMFR2_EL1_VARange_MASK
 mov x0, #VA_BITS
 mov x25, #VA_BITS_MIN
 csel x25, x25, x0, eq
 mov x0, x25
#endif
 bl __cpu_setup   // initialise processor
 b __primary_switch
SYM_CODE_END(primary_entry)
```

`preserve_boot_args`函数用来保存boot_args变量，该变量里面存储x0~x3寄存器的值，这是ARM64 Boot Protocol规定的：x0中保存dtb(设备树)的地址，x1~x3必须是0，在后续`setup_arch`函数执行时会访问boot_args并进行校验。
